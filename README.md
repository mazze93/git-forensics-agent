# git-forensics-agent

A **zero-knowledge forensic case-file agent** for adversarial git incidents —
index corruption (`fatal: unable to read <hash>`), staged repository
replacement, cross-repo coordinated tampering, and the `CLAUDE.md` semantic
attack vector.

It is the productized form of the `git-forensics` skill, built on the
**Cloudflare Agents SDK** (Durable Objects). The cloud agent is the *brain and
case file*; a thin local collector is the *hands*. The agent never runs git and
never sees your source.

---

## Why it is split the way it is

A Worker / Durable Object has **no filesystem, no `child_process`, no git**. It
physically cannot read `~/Code/*/.git/index`. And the forensic target — a
*locally* tampered index — never leaves the machine (you can't push a corrupted
index to a remote), so a cloud sandbox doesn't help either.

So evidence collection is **local and non-negotiable**, and the agent's job is
everything that benefits from being durable, correlated, and tamper-evident:
chain of custody, cross-repo correlation, and a repair gate.

```
┌───────────────────────────┐   HTTPS    ┌────────────────────────────────────┐
│ LOCAL COLLECTOR            │  (bearer)  │ CLOUDFLARE AGENT (Durable Object)   │
│ forensic-collect.mjs       │ ─────────▶ │ ForensicCaseAgent — 1 DO per case   │
│ • read-only git plumbing   │            │ • append-only evidence (SQLite)     │
│ • encrypts CONTENT locally │            │ • correlateMissingBlobs (cross-repo)│
│   (AES-256-GCM, key stays) │            │ • compareIndexToHead / replacement  │
│ • runs read-tree HEAD only │ ◀───────── │ • checkClaudeSemanticDrift (hashes) │
│   on auth + operator "yes" │  signed    │ • evidence-gated repair authorize   │
└───────────────────────────┘  token     │ • server-authoritative synced state │
        the HANDS                         └────────────────────────────────────┘
                                                   the BRAIN + CASE FILE
```

## Zero-knowledge data model

| Travels in clear (fingerprints)             | Encrypted on-device (never readable by the agent) |
| ------------------------------------------- | ------------------------------------------------- |
| git object hashes, paths, modes             | blob bodies (`git cat-file -p`)                   |
| `fatal: unable to read` hashes, fsck flags  | the staged `CLAUDE.md` text                       |
| counts, status lines, timestamps            | any captured content preview                      |

A git object id is a one-way fingerprint — it drives all correlation and even
the `CLAUDE.md` drift detection (which compares *hashes*, not content) while
revealing nothing. Content rides only as AES-256-GCM ciphertext whose key never
leaves the collector. The product can therefore truthfully claim: **"we
correlate on fingerprints we can verify but cannot read your code."**

> Paths travel in clear in v1 (needed for usable correlation and display). A
> "paranoid mode" that HMACs paths with a per-tenant pepper is a documented
> future option; the analysis functions are path-agnostic where it matters.

## Skill-action mapping

| `git-forensics` Agent API | Implementation                                                        |
| ------------------------- | --------------------------------------------------------------------- |
| `scanRepos`               | collector triage (`forensic-collect scan`)                            |
| `dumpIndexEvidence`       | `POST /ingest` → append-only `evidence` table                         |
| `compareIndexToHead`      | `src/analysis.ts:compareIndexToHead`, surfaced in findings            |
| `correlateMissingBlobs`   | `src/analysis.ts:correlateMissingBlobs`, surfaced in findings         |
| `locateBlob`              | `GET /locate?hash=` (tells the collector which repos hold the object) |
| `checkClaudeSemanticDrift`| `src/analysis.ts:checkClaudeDrift`, surfaced in findings              |
| `repairIndex`             | `POST /authorize-repair` (gate) + collector `read-tree HEAD` + `POST /repair-confirm` |

### Invariants enforced (from the skill)

- **Evidence before repair.** `/authorize-repair` returns `409` unless an
  evidence snapshot exists for that repo. The repair token is HMAC-signed and
  short-lived; the collector executes only after an operator types `yes`.
- **Append-only evidence.** `validateStateChange` rejects any decrease in
  evidence count or the repair audit log; the SQL tables are insert-only
  (authorize and confirm are *separate* rows).
- **No destructive git, ever.** The collector hard-blocks anything outside a
  read-only allow-list; the only write is `git read-tree HEAD`. `reset`,
  `clean`, `commit` are refused in code.
- **State is server-authoritative.** A dashboard client can read synced state
  but cannot mutate it (no client-side privilege escalation to "repair
  authorized").

---

## Quick start

### 1. Deploy the agent

```bash
npm install
npm run cf-typegen           # rerun after changing wrangler.jsonc

# secrets (use strong random values)
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"  # x2
npx wrangler secret put INGEST_TOKEN
npx wrangler secret put REPAIR_SIGNING_KEY

npm run deploy               # -> https://git-forensics-agent.<you>.workers.dev
```

For local dev: copy `.dev.vars.example` to `.dev.vars`, fill it, run `npm run dev`.

### 2. Make a content key (stays on your machine)

```bash
node collector/forensic-collect.mjs keygen > /dev/null   # prints key + save hint
export FORENSIC_CONTENT_KEY="…"        # or --key ~/.forensic-agent/content.key
```

### 3. Scan repos into a case

```bash
export GFA_TOKEN="$INGEST_TOKEN"
node collector/forensic-collect.mjs scan \
  --case incident-2026-06-22 \
  --url https://git-forensics-agent.you.workers.dev \
  --repos ~/Code/praxis-aegis,~/Code/context-synapse,~/Code/secure-pride
```

Set `GFA_TOKEN` in the environment for interactive use, or pass
`--token-file /path/to/0600-token-file` for unattended collectors. The legacy
`--token` option remains available, but putting a bearer on the command line
can expose it through shell history and process listings.

### 4. Watch the case

Open the Worker URL in a browser (the dashboard), enter the Worker URL, case id,
and bearer, and it polls `/summary` for findings, cross-repo correlation, and
the repair gate.

### 5. Repair (only after evidence is on file)

```bash
node collector/forensic-collect.mjs repair \
  --case incident-2026-06-22 --url … \
  --repo ~/Code/secure-pride
# → fetches authorization, asks you to type 'yes', runs `git read-tree HEAD`,
#   records the confirmed repair in the immutable audit log.
```

### Decrypt sealed content for review

```bash
node collector/forensic-collect.mjs decrypt \
  --case incident-2026-06-22 --url … \
  --id ev_… --key ~/.forensic-agent/content.key
```

---

## Develop & test

```bash
npm run check         # typecheck + tests
npm run typecheck     # tsc --noEmit
npm test              # vitest — pure analysis core (parsers, correlation, drift)
npm run dev           # wrangler dev
```

The analysis core (`src/analysis.ts`) is pure and fully unit-tested against the
skill's canonical incident (shared missing blob across repos, wholesale index
replacement, `CLAUDE.md` graft from a sibling repo).

## Threat model & limits

- **Trusts the collector host.** Evidence integrity is only as good as the
  machine running `forensic-collect`. If that host is fully compromised, it can
  submit fabricated evidence. Per-collector signing keys are a natural hardening
  step (see `collector/README.md`).
- **Bearer auth (v1).** A single shared `INGEST_TOKEN`. For multi-tenant GTM,
  swap for per-tenant keys / OAuth and prefix case ids with a tenant id.
- **Hashes are fingerprints, not secrets.** They cannot be reversed to content,
  but a party that already has candidate content could confirm a match. This is
  the standard trade-off for content-addressed correlation.
- **The agent cannot repair anything itself** — by design. It authorizes; the
  host executes; a human confirms.

## Layout

```
src/
  index.ts      Worker entry — auth gate, routing, static dashboard
  agent.ts      ForensicCaseAgent (Durable Object) — ingest, correlate, gate
  analysis.ts   pure forensic functions (unit-tested)
  crypto.ts     Web Crypto HMAC — bearer compare + repair tokens
  types.ts      shared types
  env.ts        Worker bindings
public/index.html   dashboard (Cipher Gothic, WCAG AA, no build step)
collector/forensic-collect.mjs   local read-only collector (no deps)
test/analysis.test.ts            vitest unit tests
```
