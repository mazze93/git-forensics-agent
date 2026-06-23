/**
 * Shared types for the git-forensics case-file agent.
 *
 * Vocabulary mirrors the `git-forensics` skill's Agent API so the mapping from
 * skill action -> implementation stays legible.
 */

/** One row of `git ls-files --stage` ( <mode> <sha> <stage>\t<path> ). */
export interface IndexEntry {
  mode: string;
  hash: string;
  stage: number;
  path: string;
}

/** One row of `git ls-tree -r HEAD` ( <mode> <type> <sha>\t<path> ). */
export interface TreeEntry {
  mode: string;
  type: string;
  hash: string;
  path: string;
}

/** A path/hash pair, the unit the skill diffs index vs HEAD on. */
export interface PathHash {
  hash: string;
  path: string;
}

/**
 * Opaque, client-side-encrypted content. The Worker stores this verbatim and
 * CANNOT read it — the AES key never leaves the collector. This is how blob
 * bodies and CLAUDE.md text are preserved without exposing source to the cloud.
 */
export interface SealedContent {
  /** What this ciphertext is, e.g. "blob:<hash>" or "CLAUDE.md@index". */
  label: string;
  /** Plaintext fingerprint kept in clear for correlation (a git object id). */
  hash: string;
  alg: "AES-256-GCM";
  /** base64url */
  iv: string;
  /** base64url */
  ciphertext: string;
  /** base64url GCM auth tag */
  tag: string;
}

/**
 * What the collector POSTs per repo. Everything here is STRUCTURAL METADATA
 * (hashes, paths, modes, fsck flags) — never file content. Content rides only
 * inside `sealed` as ciphertext.
 */
export interface EvidenceSubmission {
  /** basename or stable id of the repo being reported. */
  repo: string;
  /** epoch ms the collector captured this snapshot. */
  capturedAt: number;
  /** first line of `git status --short 2>&1`. */
  statusLine: string;
  /** hash from a `fatal: unable to read <hash>` error, if any. */
  missingBlobHash?: string | null;
  /** parsed `git ls-files --stage`. */
  index: IndexEntry[];
  /** parsed `git ls-tree -r HEAD` (empty if HEAD unreadable). */
  head: TreeEntry[];
  /** `git fsck --no-dangling` output lines worth flagging (badRefName, etc.). */
  fsckFlags: string[];
  /** staged CLAUDE.md blob hash, if a CLAUDE.md entry is in the index. */
  claudeStagedHash?: string | null;
  /** HEAD's CLAUDE.md blob hash, if present. */
  claudeHeadHash?: string | null;
  /** opaque encrypted content (blob previews, CLAUDE.md body). */
  sealed: SealedContent[];
  /** opaque id of the collector instance (host fingerprint), for chain-of-custody. */
  collectorId: string;
}

export type Severity = "info" | "warning" | "critical";

export interface Finding {
  kind:
    | "missing-blob"
    | "cross-repo-correlation"
    | "index-replacement"
    | "index-head-divergence"
    | "claude-semantic-drift"
    | "dirty-refs"
    | "collector-silent";
  severity: Severity;
  repo?: string;
  detail: string;
}

/** Result of comparing a staged index against HEAD. */
export interface IndexHeadDiff {
  addedOrReplaced: PathHash[];
  deleted: PathHash[];
}

/** Result of the staged-repository-replacement heuristic. */
export interface ReplacementVerdict {
  suspected: boolean;
  /** Jaccard overlap of index paths vs HEAD paths (0 = disjoint, 1 = identical). */
  overlapRatio: number;
  reason: string;
}

/** Result of the CLAUDE.md semantic-drift check. */
export interface ClaudeDriftVerdict {
  stagedHash?: string | null;
  matchesHead: boolean;
  matchesOtherRepo: { repo: string; hash: string }[];
  riskSummary: string;
}

/** Synced agent state — broadcast to the dashboard. Contains NO content. */
export interface CaseState {
  caseId: string;
  createdAt: number;
  /** distinct repos seen in this case. */
  repos: string[];
  evidenceCount: number;
  /** distinct missing blob hashes across the case. */
  missingBlobHashes: string[];
  /** hashes seen missing in >1 repo — the coordinated-activity signal. */
  correlated: { hash: string; repos: string[] }[];
  findings: Finding[];
  /** repo -> active repair authorization (evidence-gated, short-lived). */
  repairAuthorized: Record<string, { evidenceId: string; jti: string; exp: number }>;
  /** append-only audit of confirmed repairs. */
  repairsExecuted: { repo: string; at: number; operator: string }[];
  lastIngestAt?: number;
}
