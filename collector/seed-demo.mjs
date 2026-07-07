#!/usr/bin/env node
/**
 * seed-demo — post a SYNTHETIC multi-repo incident to a local `wrangler dev`
 * instance so the dashboard shows the finding engine working end-to-end:
 *   • same missing blob in two repos  -> cross-repo-correlation (critical)
 *   • CLAUDE.md staged from a sibling -> claude-semantic-drift (critical)
 *   • .DS_Store in .git/refs          -> dirty-refs (warning)
 * Demo data only — never points at real repos. Token comes from .dev.vars.
 *
 *   node collector/seed-demo.mjs [caseId]   (default: demo-incident)
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const base = process.env.GFA_URL ?? "http://localhost:8787";
const caseId = process.argv[2] ?? "demo-incident";
const devVars = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", ".dev.vars"), "utf8");
const token = devVars.match(/INGEST_TOKEN="([^"]+)"/)?.[1];
if (!token) { console.error("no INGEST_TOKEN in .dev.vars"); process.exit(1); }

const h = (c) => c.repeat(40);            // fake 40-hex object ids
const SHARED_MISSING = "b6651396" + "d".repeat(32); // the classic shared hash
const FOREIGN_CLAUDE = h("f");            // sibling's CLAUDE.md blob

const sub = (repo, over = {}) => ({
  repo, capturedAt: Date.now(), statusLine: "", missingBlobHash: null,
  index: [], head: [], fsckFlags: [], sealed: [], collectorId: "collector_demo",
  claudeStagedHash: null, claudeHeadHash: null, ...over,
});

const submissions = [
  sub("praxis-aegis", {
    statusLine: `fatal: unable to read ${SHARED_MISSING}`,
    missingBlobHash: SHARED_MISSING,
    index: [{ mode: "100644", hash: h("1"), stage: 0, path: "src/policy.ts" }],
    head:  [{ mode: "100644", type: "blob", hash: h("1"), path: "src/policy.ts" }],
  }),
  sub("secure-pride", {
    statusLine: `fatal: unable to read ${SHARED_MISSING}`,
    missingBlobHash: SHARED_MISSING,
    claudeStagedHash: FOREIGN_CLAUDE,          // staged CLAUDE.md ≠ HEAD…
    claudeHeadHash: h("a"),
    fsckFlags: ["error: refs/.DS_Store: badRefName: invalid refname format"],
    index: [
      { mode: "100644", hash: FOREIGN_CLAUDE, stage: 0, path: "CLAUDE.md" },
      { mode: "100644", hash: h("2"), stage: 0, path: "src/scanner.py" },
    ],
    head: [
      { mode: "100644", type: "blob", hash: h("a"), path: "CLAUDE.md" },
      { mode: "100644", type: "blob", hash: h("2"), path: "src/scanner.py" },
    ],
  }),
  sub("context-synapse", {                     // …and matches THIS repo's HEAD
    claudeHeadHash: FOREIGN_CLAUDE,
    index: [{ mode: "100644", hash: FOREIGN_CLAUDE, stage: 0, path: "CLAUDE.md" }],
    head:  [{ mode: "100644", type: "blob", hash: FOREIGN_CLAUDE, path: "CLAUDE.md" }],
  }),
];

const url = (p) => `${base}/agents/forensic-case-agent/${caseId}${p}`;
const hdr = { authorization: `Bearer ${token}`, "content-type": "application/json" };

const ing = await fetch(url("/ingest"), { method: "POST", headers: hdr, body: JSON.stringify({ submissions }) });
console.log("ingest:", ing.status, await ing.text());

const sum = await fetch(url("/summary"), { headers: hdr }).then((r) => r.json());
console.log(`\ncase '${caseId}': ${sum.evidenceCount} evidence, ${sum.findings.length} findings`);
for (const f of sum.findings) console.log(`  [${f.severity}] ${f.kind}${f.repo ? ` (${f.repo})` : ""}`);
console.log(`\ndashboard: ${base}  → case '${caseId}' + token from .dev.vars`);
