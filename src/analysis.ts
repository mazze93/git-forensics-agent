/**
 * Pure forensic analysis — no I/O, no git, no network. Every function here is a
 * deterministic transform over parsed git plumbing output, so it is fully
 * unit-testable (see test/analysis.test.ts) and runs identically in the Worker
 * or in the collector.
 *
 * Each export corresponds to an action in the `git-forensics` skill's Agent API.
 */

import type {
  IndexEntry,
  TreeEntry,
  PathHash,
  IndexHeadDiff,
  ReplacementVerdict,
  ClaudeDriftVerdict,
  EvidenceSubmission,
  Finding,
} from "./types";

// ---------------------------------------------------------------------------
// Parsers — tolerant by design. A corrupted index is exactly when these run,
// so they must not throw on malformed/abbreviated/missing hashes.
// ---------------------------------------------------------------------------

/** Parse `git ls-files --stage`: `<mode> <sha> <stage>\t<path>`. */
export function parseLsFilesStage(output: string): IndexEntry[] {
  const out: IndexEntry[] = [];
  for (const raw of output.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (!line) continue;
    const tab = line.indexOf("\t");
    if (tab === -1) continue;
    const meta = line.slice(0, tab).trim().split(/\s+/);
    const path = line.slice(tab + 1);
    if (meta.length < 3) continue;
    const [mode, hash, stageStr] = meta;
    out.push({
      mode: mode ?? "",
      hash: hash ?? "",
      stage: Number.parseInt(stageStr ?? "0", 10) || 0,
      path,
    });
  }
  return out;
}

/** Parse `git ls-tree -r HEAD`: `<mode> <type> <sha>\t<path>`. */
export function parseLsTree(output: string): TreeEntry[] {
  const out: TreeEntry[] = [];
  for (const raw of output.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (!line) continue;
    const tab = line.indexOf("\t");
    if (tab === -1) continue;
    const meta = line.slice(0, tab).trim().split(/\s+/);
    const path = line.slice(tab + 1);
    if (meta.length < 3) continue;
    const [mode, type, hash] = meta;
    out.push({ mode: mode ?? "", type: type ?? "", hash: hash ?? "", path });
  }
  return out;
}

/** Extract the hash from a `fatal: unable to read <hash>` error line, if any. */
export function parseMissingBlobHash(statusOutput: string): string | null {
  const m = statusOutput.match(/unable to read ([0-9a-f]{7,64})/i);
  return m ? m[1]!.toLowerCase() : null;
}

// ---------------------------------------------------------------------------
// compareIndexToHead  (skill action: compareIndexToHead)
// ---------------------------------------------------------------------------

const key = (e: PathHash) => `${e.hash}\t${e.path}`;

/**
 * Diff staged entries vs HEAD on (hash, path) pairs — the same semantics as the
 * skill's `diff staged.txt head.txt`:
 *   addedOrReplaced = present in index, not in HEAD  ("<")
 *   deleted         = present in HEAD, not in index  (">")
 */
export function compareIndexToHead(index: IndexEntry[], head: TreeEntry[]): IndexHeadDiff {
  const headKeys = new Set(head.map((e) => key(e)));
  const indexKeys = new Set(index.map((e) => key(e)));

  const addedOrReplaced = index
    .filter((e) => !headKeys.has(key(e)))
    .map(({ hash, path }) => ({ hash, path }));

  const deleted = head
    .filter((e) => !indexKeys.has(key(e)))
    .map(({ hash, path }) => ({ hash, path }));

  return { addedOrReplaced, deleted };
}

// ---------------------------------------------------------------------------
// detectIndexReplacement  (skill: "Staged Repository Replacement")
// ---------------------------------------------------------------------------

/**
 * Heuristic for a wholesale index replacement: the staged paths belong to a
 * different project than HEAD. Measured as Jaccard overlap of the two path
 * sets. Low overlap with both sides non-trivially populated => suspected.
 */
export function detectIndexReplacement(
  index: IndexEntry[],
  head: TreeEntry[],
  opts: { minOverlap?: number; minPaths?: number } = {},
): ReplacementVerdict {
  const minOverlap = opts.minOverlap ?? 0.1;
  const minPaths = opts.minPaths ?? 3;

  const idxPaths = new Set(index.map((e) => e.path));
  const headPaths = new Set(head.map((e) => e.path));

  if (idxPaths.size < minPaths || headPaths.size < minPaths) {
    return {
      suspected: false,
      overlapRatio: 1,
      reason: "Too few paths to assess replacement reliably.",
    };
  }

  let inter = 0;
  for (const p of idxPaths) if (headPaths.has(p)) inter++;
  const union = idxPaths.size + headPaths.size - inter;
  const overlapRatio = union === 0 ? 1 : inter / union;

  const suspected = overlapRatio <= minOverlap;
  return {
    suspected,
    overlapRatio,
    reason: suspected
      ? `Staged path set shares only ${(overlapRatio * 100).toFixed(1)}% with HEAD — ` +
        `consistent with the index being replaced by another project's index.`
      : `Staged and HEAD path sets overlap ${(overlapRatio * 100).toFixed(1)}% — no wholesale replacement signal.`,
  };
}

// ---------------------------------------------------------------------------
// correlateMissingBlobs  (skill action: correlateMissingBlobs)
// ---------------------------------------------------------------------------

/**
 * Map each missing-blob hash to the repos it appeared in. A hash mapping to >1
 * repo is the coordinated-activity signal the skill calls out.
 */
export function correlateMissingBlobs(
  repos: { repo: string; missingBlobHash?: string | null }[],
): Record<string, string[]> {
  const map: Record<string, string[]> = {};
  for (const { repo, missingBlobHash } of repos) {
    if (!missingBlobHash) continue;
    const h = missingBlobHash.toLowerCase();
    (map[h] ??= []);
    if (!map[h]!.includes(repo)) map[h]!.push(repo);
  }
  return map;
}

// ---------------------------------------------------------------------------
// checkClaudeDrift  (skill action: checkClaudeSemanticDrift)
// ---------------------------------------------------------------------------

/**
 * Compare a staged CLAUDE.md hash against this repo's HEAD and against known
 * CLAUDE.md hashes from sibling repos. Detection needs only HASHES — the actual
 * (potentially poisoned) content stays encrypted client-side.
 */
export function checkClaudeDrift(params: {
  stagedHash?: string | null;
  headHash?: string | null;
  referenceHashes: { repo: string; hash: string }[];
}): ClaudeDriftVerdict {
  const staged = params.stagedHash?.toLowerCase() ?? null;
  const head = params.headHash?.toLowerCase() ?? null;

  if (!staged) {
    return {
      stagedHash: null,
      matchesHead: false,
      matchesOtherRepo: [],
      riskSummary: "No CLAUDE.md staged in the index — no semantic-control-plane change detected.",
    };
  }

  const matchesHead = !!head && staged === head;
  const matchesOtherRepo = params.referenceHashes
    .filter((r) => r.hash.toLowerCase() === staged)
    .map((r) => ({ repo: r.repo, hash: staged }));

  let riskSummary: string;
  if (matchesHead) {
    riskSummary = "Staged CLAUDE.md matches HEAD — unchanged governance file, low risk.";
  } else if (matchesOtherRepo.length > 0) {
    riskSummary =
      `Staged CLAUDE.md does NOT match HEAD but DOES match CLAUDE.md from ` +
      `${matchesOtherRepo.map((r) => r.repo).join(", ")}. Consistent with a foreign governance ` +
      `file being grafted into this repo to recontextualize future AI sessions. High risk — inspect content.`;
  } else {
    riskSummary =
      "Staged CLAUDE.md differs from HEAD and matches no known sibling baseline — " +
      "unrecognized governance content staged. Treat as suspicious; decrypt and review before any commit.";
  }

  return { stagedHash: staged, matchesHead, matchesOtherRepo, riskSummary };
}

// ---------------------------------------------------------------------------
// deriveFindings — fold per-repo evidence + cross-repo correlation into a
// ranked Finding[]. This is what the agent surfaces to the dashboard.
// ---------------------------------------------------------------------------

export function deriveFindings(
  submissions: EvidenceSubmission[],
): { findings: Finding[]; correlated: { hash: string; repos: string[] }[] } {
  const findings: Finding[] = [];

  // Cross-repo missing-blob correlation.
  const corrMap = correlateMissingBlobs(
    submissions.map((s) => ({ repo: s.repo, missingBlobHash: s.missingBlobHash })),
  );
  const correlated = Object.entries(corrMap)
    .map(([hash, repos]) => ({ hash, repos }))
    .sort((a, b) => b.repos.length - a.repos.length);

  for (const { hash, repos } of correlated) {
    if (repos.length > 1) {
      findings.push({
        kind: "cross-repo-correlation",
        severity: "critical",
        detail:
          `Missing blob ${hash.slice(0, 12)}… shared by ${repos.length} repos ` +
          `(${repos.join(", ")}). A shared hash implies the same write was attempted ` +
          `across repos and interrupted — coordinated activity, not isolated corruption.`,
      });
    } else {
      findings.push({
        kind: "missing-blob",
        severity: "warning",
        repo: repos[0],
        detail: `Missing blob ${hash.slice(0, 12)}… in ${repos[0]} (\`fatal: unable to read\`).`,
      });
    }
  }

  // Build sibling CLAUDE.md baseline from every repo's HEAD hash.
  const claudeRefs = submissions
    .filter((s) => s.claudeHeadHash)
    .map((s) => ({ repo: s.repo, hash: s.claudeHeadHash as string }));

  // Per-repo structural analysis.
  for (const s of submissions) {
    const diff = compareIndexToHead(s.index, s.head);
    const replacement = detectIndexReplacement(s.index, s.head);

    if (replacement.suspected) {
      findings.push({
        kind: "index-replacement",
        severity: "critical",
        repo: s.repo,
        detail: replacement.reason,
      });
    } else if (diff.addedOrReplaced.length > 0 || diff.deleted.length > 0) {
      const sev =
        diff.addedOrReplaced.length + diff.deleted.length > 25 ? "warning" : "info";
      findings.push({
        kind: "index-head-divergence",
        severity: sev,
        repo: s.repo,
        detail:
          `Index diverges from HEAD: ${diff.addedOrReplaced.length} added/replaced, ` +
          `${diff.deleted.length} deleted. Review staged entries before committing.`,
      });
    }

    if (s.claudeStagedHash) {
      const drift = checkClaudeDrift({
        stagedHash: s.claudeStagedHash,
        headHash: s.claudeHeadHash,
        referenceHashes: claudeRefs.filter((r) => r.repo !== s.repo),
      });
      if (!drift.matchesHead) {
        findings.push({
          kind: "claude-semantic-drift",
          severity: drift.matchesOtherRepo.length > 0 ? "critical" : "warning",
          repo: s.repo,
          detail: drift.riskSummary,
        });
      }
    }

    if (s.fsckFlags.length > 0) {
      findings.push({
        kind: "dirty-refs",
        severity: "warning",
        repo: s.repo,
        detail: `fsck flagged: ${s.fsckFlags.join("; ")}. Possible ref contamination (e.g. .DS_Store in .git/refs).`,
      });
    }
  }

  const rank: Record<Finding["severity"], number> = { critical: 0, warning: 1, info: 2 };
  findings.sort((a, b) => rank[a.severity] - rank[b.severity]);

  return { findings, correlated };
}
