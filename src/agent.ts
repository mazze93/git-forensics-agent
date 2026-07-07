/**
 * ForensicCaseAgent — one Durable Object instance per investigation ("case").
 *
 * It is the BRAIN and the CASE FILE: it ingests read-only git plumbing evidence
 * from local collectors, correlates it across repos, runs the git-forensics
 * detections, and gates repair behind preserved evidence. It never runs git and
 * never sees plaintext file content (content arrives pre-encrypted and is stored
 * opaque).
 *
 * Skill action mapping:
 *   scanRepos              -> performed by the collector; results arrive via /ingest
 *   dumpIndexEvidence      -> POST /ingest  (append-only persist)
 *   compareIndexToHead     -> analysis.compareIndexToHead, surfaced in findings
 *   correlateMissingBlobs  -> analysis.correlateMissingBlobs, surfaced in findings
 *   locateBlob             -> GET /locate?hash= (tells collector which repos saw it)
 *   checkClaudeSemanticDrift -> analysis.checkClaudeDrift, surfaced in findings
 *   repairIndex            -> POST /authorize-repair (gate) + POST /repair-confirm (record)
 */
import { Agent, callable, type Connection } from "agents";
import type { Schedule } from "agents";
import type { Env } from "./env";
import type { CaseState, EvidenceSubmission, Finding, SealedContent } from "./types";
import { deriveFindings } from "./analysis";
import { signRepairToken, verifyRepairToken, randomId } from "./crypto";

/** Repair authorizations expire fast — the collector must act promptly. */
const REPAIR_TTL_MS = 10 * 60 * 1000; // 10 minutes
/** If no evidence arrives within this window, flag the collector as silent. */
const STALE_WINDOW_MS = 6 * 60 * 60 * 1000; // 6 hours
/** Reject absurd payloads early. */
const MAX_BODY_BYTES = 8 * 1024 * 1024;

interface EvidenceRow {
  id: string;
  repo: string;
  captured_at: number;
  raw_meta: string;
  sealed_content: string;
}

const json = (data: unknown, status = 200): Response =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });

export class ForensicCaseAgent extends Agent<Env, CaseState> {
  initialState: CaseState = {
    caseId: "",
    createdAt: 0,
    repos: [],
    evidenceCount: 0,
    missingBlobHashes: [],
    correlated: [],
    findings: [],
    repairAuthorized: {},
    repairsExecuted: [],
  };

  async onStart() {
    this.sql`
      CREATE TABLE IF NOT EXISTS evidence (
        id              TEXT PRIMARY KEY,
        repo            TEXT NOT NULL,
        captured_at     INTEGER NOT NULL,
        collector_id    TEXT,
        missing_blob    TEXT,
        raw_meta        TEXT NOT NULL,   -- JSON: structural metadata only (NO content)
        sealed_content  TEXT NOT NULL,   -- JSON SealedContent[] — opaque ciphertext
        received_at     INTEGER NOT NULL
      )`;
    this.sql`
      CREATE TABLE IF NOT EXISTS missing_blobs (
        hash        TEXT NOT NULL,
        repo        TEXT NOT NULL,
        evidence_id TEXT NOT NULL,
        seen_at     INTEGER NOT NULL
      )`;
    // Chain-of-custody: append-only. Authorize and confirm are SEPARATE rows.
    this.sql`
      CREATE TABLE IF NOT EXISTS repair_log (
        jti          TEXT NOT NULL,
        event        TEXT NOT NULL,      -- 'authorized' | 'confirmed'
        repo         TEXT NOT NULL,
        evidence_id  TEXT,
        executed     INTEGER,
        operator     TEXT,
        at           INTEGER NOT NULL
      )`;

    if (!this.state.caseId) {
      this.setState({
        ...this.state,
        caseId: this.name ?? "default",
        createdAt: Date.now(),
      });
    }
  }

  // -------------------------------------------------------------------------
  // State integrity. State is SERVER-AUTHORITATIVE: a dashboard/client may read
  // synced state but may never mutate it (a client must not be able to
  // authorize a repair or rewrite findings). Server writes are additionally
  // checked for append-only monotonicity to catch our own bugs.
  // -------------------------------------------------------------------------
  validateStateChange(_next: CaseState, source: Connection | "server") {
    // State is server-authoritative: a dashboard/client may read synced state
    // but never mutate it (no client-side escalation to "repair authorized").
    // Do NOT read this.state here — the getter re-enters during a write and
    // recurses. Append-only integrity is enforced by insert-only SQL, not here.
    if (source !== "server") {
      throw new Error("Forensic state is server-authoritative; client mutations are rejected.");
    }
  }

  // -------------------------------------------------------------------------
  // HTTP surface (collector + dashboard). Routed here for any subpath after the
  // instance name, e.g. /agents/forensic-case-agent/<case>/ingest.
  // -------------------------------------------------------------------------
  async onRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);
    const sub = "/" + parts.slice(3).join("/"); // strip /agents/<class>/<name>

    try {
      if (request.method === "POST" && sub === "/ingest") return await this.handleIngest(request);
      if (request.method === "GET" && sub === "/summary") return json(this.summarySnapshot());
      if (request.method === "GET" && sub === "/locate") return this.handleLocate(url);
      if (request.method === "POST" && sub === "/authorize-repair") return await this.handleAuthorize(request);
      if (request.method === "POST" && sub === "/repair-confirm") return await this.handleConfirm(request);
      if (request.method === "GET" && sub.startsWith("/evidence/")) return this.handleSealed(parts);
      return json({ error: "not found", path: sub }, 404);
    } catch (err) {
      return json({ error: err instanceof Error ? err.message : "internal error" }, 400);
    }
  }

  private async readJson(request: Request): Promise<unknown> {
    const len = Number(request.headers.get("content-length") ?? "0");
    if (len > MAX_BODY_BYTES) throw new Error("payload too large");
    const text = await request.text();
    if (text.length > MAX_BODY_BYTES) throw new Error("payload too large");
    return JSON.parse(text);
  }

  // ---- /ingest ------------------------------------------------------------
  private async handleIngest(request: Request): Promise<Response> {
    const body = (await this.readJson(request)) as
      | EvidenceSubmission
      | { submissions: EvidenceSubmission[] };
    const submissions: EvidenceSubmission[] = Array.isArray(
      (body as { submissions?: unknown }).submissions,
    )
      ? (body as { submissions: EvidenceSubmission[] }).submissions
      : [body as EvidenceSubmission];

    const accepted: string[] = [];
    for (const s of submissions) {
      if (!s || typeof s.repo !== "string" || !Array.isArray(s.index)) {
        throw new Error("malformed submission: requires { repo, index, ... }");
      }
      const id = randomId("ev_");
      const meta = { ...s, sealed: undefined }; // store metadata WITHOUT content
      const sealed: SealedContent[] = Array.isArray(s.sealed) ? s.sealed : [];

      this.sql`
        INSERT INTO evidence (id, repo, captured_at, collector_id, missing_blob, raw_meta, sealed_content, received_at)
        VALUES (${id}, ${s.repo}, ${s.capturedAt ?? Date.now()}, ${s.collectorId ?? ""},
                ${s.missingBlobHash ?? null}, ${JSON.stringify(meta)}, ${JSON.stringify(sealed)}, ${Date.now()})`;

      if (s.missingBlobHash) {
        this.sql`
          INSERT INTO missing_blobs (hash, repo, evidence_id, seen_at)
          VALUES (${s.missingBlobHash.toLowerCase()}, ${s.repo}, ${id}, ${Date.now()})`;
      }
      accepted.push(id);
    }

    this.recomputeState();

    // (Re)arm the tripwire staleness check. One-shot, re-armed on each ingest,
    // so a dormant case eventually stops scheduling — bounded resource use.
    await this.schedule(STALE_WINDOW_MS / 1000, "staleCheck", {});

    return json({ ok: true, accepted, evidenceCount: this.state.evidenceCount });
  }

  /** Load the latest submission metadata per repo and recompute findings/state. */
  private recomputeState() {
    const rows = this.sql<EvidenceRow>`
      SELECT e.* FROM evidence e
      JOIN (SELECT repo, MAX(captured_at) AS m FROM evidence GROUP BY repo) g
        ON e.repo = g.repo AND e.captured_at = g.m`;

    const latest: EvidenceSubmission[] = rows.map((r) => {
      const meta = JSON.parse(r.raw_meta) as EvidenceSubmission;
      // ensure required arrays exist even if an older payload omitted them
      meta.index ??= [];
      meta.head ??= [];
      meta.fsckFlags ??= [];
      meta.sealed = [];
      return meta;
    });

    const { findings, correlated } = deriveFindings(latest);
    const repos = [...new Set(latest.map((s) => s.repo))].sort();
    const totalCount = (this.sql<{ c: number }>`SELECT COUNT(*) AS c FROM evidence`)[0]?.c ?? 0;
    const missingHashes = [
      ...new Set(
        (this.sql<{ hash: string }>`SELECT DISTINCT hash FROM missing_blobs`).map((r) => r.hash),
      ),
    ];

    this.setState({
      ...this.state,
      caseId: this.state.caseId || (this.name ?? "default"),
      createdAt: this.state.createdAt || Date.now(),
      repos,
      evidenceCount: totalCount,
      missingBlobHashes: missingHashes,
      correlated,
      findings,
      lastIngestAt: Date.now(),
    });
  }

  // ---- /locate (skill: locateBlob) ---------------------------------------
  // The agent can't read object stores, but it knows which repos *reported* a
  // hash (as a missing blob or an index/head entry). That tells the collector
  // where to run `git cat-file -p <hash>` locally.
  private handleLocate(url: URL): Response {
    const hash = (url.searchParams.get("hash") ?? "").toLowerCase();
    if (!/^[0-9a-f]{7,64}$/.test(hash)) return json({ error: "invalid hash" }, 400);

    const reportedMissingIn = (this.sql<{ repo: string }>`
      SELECT DISTINCT repo FROM missing_blobs WHERE hash = ${hash}`).map((r) => r.repo);

    const rows = this.sql<EvidenceRow>`SELECT id, repo, captured_at, raw_meta, sealed_content FROM evidence`;
    const seenInIndexOf = new Set<string>();
    for (const r of rows) {
      const meta = JSON.parse(r.raw_meta) as EvidenceSubmission;
      const inIndex = (meta.index ?? []).some((e) => e.hash.toLowerCase() === hash);
      const inHead = (meta.head ?? []).some((e) => e.hash.toLowerCase() === hash);
      if (inIndex || inHead) seenInIndexOf.add(r.repo);
    }
    return json({
      hash,
      reportedMissingIn,
      presentInTreeOrIndexOf: [...seenInIndexOf],
      hint: "Run `git cat-file -p <hash>` in one of presentInTreeOrIndexOf to recover content.",
    });
  }

  // ---- /authorize-repair  (the repair GATE) ------------------------------
  // Refuses unless an evidence snapshot exists for the repo. This is the
  // implementation of the skill's invariant: "Never perform repair before at
  // least one successful evidence snapshot for the same repo."
  private async handleAuthorize(request: Request): Promise<Response> {
    const { repo } = (await this.readJson(request)) as { repo?: string };
    if (!repo) return json({ error: "repo required" }, 400);

    const ev = (this.sql<{ id: string }>`
      SELECT id FROM evidence WHERE repo = ${repo} ORDER BY captured_at DESC LIMIT 1`)[0];
    if (!ev) {
      return json(
        {
          error: "repair refused",
          reason:
            "No evidence snapshot on file for this repo. Capture evidence (POST /ingest) before requesting repair.",
        },
        409,
      );
    }

    const now = Date.now();
    const jti = randomId("jti_");
    const exp = now + REPAIR_TTL_MS;
    const token = await signRepairToken(this.env.REPAIR_SIGNING_KEY, {
      caseId: this.state.caseId || (this.name ?? "default"),
      repo,
      evidenceId: ev.id,
      jti,
      action: "read-tree-head",
      iat: now,
      exp,
    });

    this.sql`
      INSERT INTO repair_log (jti, event, repo, evidence_id, executed, operator, at)
      VALUES (${jti}, 'authorized', ${repo}, ${ev.id}, NULL, NULL, ${now})`;

    this.setState({
      ...this.state,
      repairAuthorized: {
        ...this.state.repairAuthorized,
        [repo]: { evidenceId: ev.id, jti, exp },
      },
    });

    return json({
      ok: true,
      repo,
      evidenceId: ev.id,
      token,
      exp,
      action: "git read-tree HEAD",
      note: "Token is single-use and expires. Collector must obtain operator confirmation before executing.",
    });
  }

  // ---- /repair-confirm  (record execution after operator confirm) --------
  private async handleConfirm(request: Request): Promise<Response> {
    const { repo, token, executed, operator } = (await this.readJson(request)) as {
      repo?: string;
      token?: string;
      executed?: boolean;
      operator?: string;
    };
    if (!repo || !token) return json({ error: "repo and token required" }, 400);

    const v = await verifyRepairToken(this.env.REPAIR_SIGNING_KEY, token);
    if (!v.valid || !v.payload) return json({ error: "invalid token", reason: v.reason }, 403);
    if (v.payload.repo !== repo) return json({ error: "token/repo mismatch" }, 403);

    const authorized = (this.sql<{ jti: string }>`
      SELECT jti FROM repair_log WHERE jti = ${v.payload.jti} AND event = 'authorized' LIMIT 1`)[0];
    if (!authorized) return json({ error: "no matching authorization" }, 409);

    const already = (this.sql<{ jti: string }>`
      SELECT jti FROM repair_log WHERE jti = ${v.payload.jti} AND event = 'confirmed' LIMIT 1`)[0];
    if (already) return json({ error: "authorization already used" }, 409);

    const now = Date.now();
    this.sql`
      INSERT INTO repair_log (jti, event, repo, evidence_id, executed, operator, at)
      VALUES (${v.payload.jti}, 'confirmed', ${repo}, ${v.payload.evidenceId},
              ${executed ? 1 : 0}, ${operator ?? "unknown"}, ${now})`;

    const remaining = { ...this.state.repairAuthorized };
    delete remaining[repo];
    this.setState({
      ...this.state,
      repairAuthorized: remaining,
      repairsExecuted: executed
        ? [...this.state.repairsExecuted, { repo, at: now, operator: operator ?? "unknown" }]
        : this.state.repairsExecuted,
    });

    return json({ ok: true, recorded: executed ? "repair-executed" : "repair-declined" });
  }

  // ---- /evidence/:id/sealed  (return opaque ciphertext for LOCAL decrypt) -
  private handleSealed(parts: string[]): Response {
    const id = parts[4]; // /agents/<class>/<name>/evidence/<id>/sealed
    if (!id) return json({ error: "evidence id required" }, 400);
    const row = (this.sql<{ sealed_content: string }>`
      SELECT sealed_content FROM evidence WHERE id = ${id} LIMIT 1`)[0];
    if (!row) return json({ error: "not found" }, 404);
    // The Worker cannot decrypt this. The caller decrypts locally with their key.
    return json({ id, sealed: JSON.parse(row.sealed_content) });
  }

  // ---- tripwire staleness check ------------------------------------------
  async staleCheck(_payload: unknown, _schedule: Schedule<unknown>) {
    const last = this.state.lastIngestAt ?? 0;
    if (Date.now() - last < STALE_WINDOW_MS) return; // fresh enough
    const already = this.state.findings.some((f) => f.kind === "collector-silent");
    if (already) return;
    const finding: Finding = {
      kind: "collector-silent",
      severity: "warning",
      detail:
        `No evidence received in over ${Math.round(STALE_WINDOW_MS / 3600000)}h. ` +
        `If a collector cron is expected, its silence may itself indicate tampering or a disabled tripwire.`,
    };
    this.setState({ ...this.state, findings: [finding, ...this.state.findings] });
  }

  // -------------------------------------------------------------------------
  // RPC surface (dashboard / typed clients). Mirrors the read + gate actions.
  // -------------------------------------------------------------------------
  @callable()
  summary(): CaseState & { authActive: number } {
    return this.summarySnapshot();
  }

  @callable()
  async authorizeRepair(repo: string): Promise<unknown> {
    return (await this.handleAuthorize(
      new Request("https://internal/authorize-repair", {
        method: "POST",
        body: JSON.stringify({ repo }),
      }),
    )).json();
  }

  private summarySnapshot(): CaseState & { authActive: number } {
    return { ...this.state, authActive: Object.keys(this.state.repairAuthorized).length };
  }
}
