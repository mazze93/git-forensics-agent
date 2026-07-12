#!/usr/bin/env node
/**
 * forensic-collect — local, read-only git-forensics collector for the
 * git-forensics-agent. Runs on the machine that owns the repos (your Mac /
 * m3.local). It is the only component that touches a repo.
 *
 * Invariants (mirroring the git-forensics skill, enforced in code below):
 *   - Only read-only plumbing is ever run: status, ls-files, ls-tree, fsck,
 *     cat-file, rev-parse. The single write is `git read-tree HEAD`, and only
 *     in the `repair` subcommand, only after agent authorization AND an explicit
 *     operator "yes". reset / clean / commit are hard-blocked by an allow-list.
 *   - File CONTENT is encrypted on-device (AES-256-GCM) before upload. The key
 *     never leaves this machine. The agent stores ciphertext it cannot read.
 *
 * No npm dependencies — Node >= 20 (uses global fetch, node:crypto, spawnSync).
 *
 * Usage:
 *   forensic-collect keygen
 *   GFA_TOKEN=<ingest> forensic-collect scan --case <id> --url <https://worker> \
 *                           --repos /path/a,/path/b [--key <file|base64>] [--no-content]
 *   GFA_TOKEN=<ingest> forensic-collect repair --case <id> --url <...> --repo /path/a
 *   GFA_TOKEN=<ingest> forensic-collect decrypt --case <id> --url <...> --id <evidenceId> --key <...>
 * `--token-file` is preferred for unattended use; `--token` remains supported
 * for compatibility but can leak through shell history and process listings.
 */
import { spawnSync } from "node:child_process";
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHash,
} from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { hostname } from "node:os";
import { basename } from "node:path";

// --- git command allow-list ------------------------------------------------
const READONLY = new Set(["status", "ls-files", "ls-tree", "fsck", "cat-file", "rev-parse"]);
const REPAIR = new Set(["read-tree"]);
const HTTP_TIMEOUT_MS = 15_000;

function git(repo, args, { repair = false } = {}) {
  const sub = args[0];
  const allowed = repair ? REPAIR.has(sub) : READONLY.has(sub);
  if (!allowed) {
    throw new Error(`refused: 'git ${sub}' is not in the forensic command allow-list`);
  }
  const r = spawnSync("git", ["-C", repo, ...args], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return { code: r.status ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

function isGitRepo(repo) {
  return git(repo, ["rev-parse", "--is-inside-work-tree"]).stdout.trim() === "true";
}

// --- crypto (client-side content sealing) ----------------------------------
function loadKey(keyArg) {
  const value = keyArg
    ? existsSync(keyArg)
      ? readFileSync(keyArg, "utf8").trim()
      : keyArg
    : process.env.FORENSIC_CONTENT_KEY;
  if (!value) return null;
  const key = b64urlToBuf(value);
  if (key.length !== 32) {
    throw new Error("content key must decode to exactly 32 bytes (AES-256)");
  }
  return key;
}

function b64url(buf) {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBuf(s) {
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function seal(key, label, hash, plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  return {
    label,
    hash,
    alg: "AES-256-GCM",
    iv: b64url(iv),
    ciphertext: b64url(ct),
    tag: b64url(cipher.getAuthTag()),
  };
}

function unseal(key, sealed) {
  const d = createDecipheriv("aes-256-gcm", key, b64urlToBuf(sealed.iv));
  d.setAuthTag(b64urlToBuf(sealed.tag));
  return Buffer.concat([d.update(b64urlToBuf(sealed.ciphertext)), d.final()]).toString("utf8");
}

// --- parsing (mirrors src/analysis.ts so the collector can self-summarize) --
function parseLsFilesStage(out) {
  const rows = [];
  for (const line of out.split("\n")) {
    const tab = line.indexOf("\t");
    if (tab === -1) continue;
    const meta = line.slice(0, tab).trim().split(/\s+/);
    if (meta.length < 3) continue;
    rows.push({ mode: meta[0], hash: meta[1], stage: parseInt(meta[2], 10) || 0, path: line.slice(tab + 1) });
  }
  return rows;
}
function parseLsTree(out) {
  const rows = [];
  for (const line of out.split("\n")) {
    const tab = line.indexOf("\t");
    if (tab === -1) continue;
    const meta = line.slice(0, tab).trim().split(/\s+/);
    if (meta.length < 3) continue;
    rows.push({ mode: meta[0], type: meta[1], hash: meta[2], path: line.slice(tab + 1) });
  }
  return rows;
}
function missingBlobFrom(text) {
  const m = text.match(/unable to read ([0-9a-f]{7,64})/i);
  return m ? m[1].toLowerCase() : null;
}
const collectorId = () => "collector_" + createHash("sha256").update(hostname()).digest("hex").slice(0, 12);

// --- evidence capture for one repo -----------------------------------------
function captureRepo(repo, key, withContent) {
  if (!isGitRepo(repo)) throw new Error(`${repo}: not a git work tree`);
  const name = basename(repo);

  const status = git(repo, ["status", "--short"]);
  const statusText = status.stdout + status.stderr;
  const statusLine = statusText.split("\n").find((l) => l.trim()) ?? "";
  const missingBlobHash = missingBlobFrom(statusText);

  const index = parseLsFilesStage(git(repo, ["ls-files", "--stage"]).stdout);
  const headOut = git(repo, ["ls-tree", "-r", "HEAD"]);
  const head = headOut.code === 0 ? parseLsTree(headOut.stdout) : [];

  const fsck = git(repo, ["fsck", "--no-dangling"]);
  const fsckFlags = (fsck.stdout + fsck.stderr)
    .split("\n")
    .filter((l) => /badRefName|DS_Store|error|missing|corrupt/i.test(l))
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(0, 25);

  const claudeIdx = index.find((e) => /(^|\/)CLAUDE\.md$/.test(e.path));
  const claudeHead = head.find((e) => /(^|\/)CLAUDE\.md$/.test(e.path));
  const claudeStagedHash = claudeIdx?.hash ?? null;
  const claudeHeadHash = claudeHead?.hash ?? null;

  // Seal CONTENT (only if a key is provided and content capture is on).
  const sealed = [];
  if (key && withContent) {
    if (claudeStagedHash) {
      const body = git(repo, ["cat-file", "-p", claudeStagedHash]);
      if (body.code === 0) sealed.push(seal(key, "CLAUDE.md@index", claudeStagedHash, body.stdout));
    }
    // Truncated previews of staged-but-not-in-HEAD blobs (cap to keep lean).
    const headKeys = new Set(head.map((e) => `${e.hash}\t${e.path}`));
    const changed = index.filter((e) => !headKeys.has(`${e.hash}\t${e.path}`)).slice(0, 20);
    for (const e of changed) {
      if (!/^[0-9a-f]{40}$|^[0-9a-f]{64}$/.test(e.hash)) continue; // skip missing/garbage
      const t = git(repo, ["cat-file", "-t", e.hash]);
      if (t.stdout.trim() !== "blob") continue;
      const body = git(repo, ["cat-file", "-p", e.hash]);
      if (body.code === 0) sealed.push(seal(key, `blob:${e.path}`, e.hash, body.stdout.slice(0, 4096)));
    }
  }

  return {
    repo: name,
    capturedAt: Date.now(),
    statusLine,
    missingBlobHash,
    index,
    head,
    fsckFlags,
    claudeStagedHash,
    claudeHeadHash,
    sealed,
    collectorId: collectorId(),
  };
}

// --- HTTP ------------------------------------------------------------------
function agentUrl(base, caseId, path) {
  return `${base.replace(/\/$/, "")}/agents/forensic-case-agent/${encodeURIComponent(caseId)}${path}`;
}
async function post(url, token, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data };
}
async function get(url, token) {
  const res = await fetch(url, {
    headers: { authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data };
}

// --- arg parsing -----------------------------------------------------------
function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const k = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) out[k] = true;
      else { out[k] = next; i++; }
    } else out._.push(a);
  }
  return out;
}

function die(msg) { console.error(`✗ ${msg}`); process.exit(1); }

function resolveToken(a) {
  if (a["token-file"]) return readFileSync(String(a["token-file"]), "utf8").trim();
  return String(a.token ?? process.env.GFA_TOKEN ?? "").trim();
}

// --- subcommands -----------------------------------------------------------
async function cmdScan(a) {
  const token = resolveToken(a);
  if (!a.url || !token || !a.case || !a.repos) {
    die("scan needs --case --url --repos and GFA_TOKEN, --token-file, or --token");
  }
  const repos = String(a.repos).split(",").map((s) => s.trim()).filter(Boolean);
  const key = loadKey(a.key);
  const withContent = !a["no-content"];
  if (withContent && !key) {
    console.error("⚠ no content key (FORENSIC_CONTENT_KEY or --key); uploading METADATA ONLY.");
  }

  const submissions = [];
  for (const repo of repos) {
    try {
      const sub = captureRepo(repo, key, withContent);
      submissions.push(sub);
      const sig = sub.missingBlobHash ? ` missing-blob=${sub.missingBlobHash.slice(0, 10)}…` : "";
      console.error(`• ${sub.repo}: idx=${sub.index.length} head=${sub.head.length} sealed=${sub.sealed.length}${sig}`);
    } catch (e) {
      console.error(`✗ ${repo}: ${e.message}`);
    }
  }
  if (!submissions.length) die("no repos captured");

  const { status, data } = await post(agentUrl(a.url, a.case, "/ingest"), token, { submissions });
  if (status !== 200) die(`ingest failed (${status}): ${JSON.stringify(data)}`);
  console.log(`✓ ingested ${submissions.length} repo(s) into case '${a.case}'. evidenceCount=${data.evidenceCount}`);
}

async function cmdRepair(a) {
  const bearer = resolveToken(a);
  if (!a.url || !bearer || !a.case || !a.repo) {
    die("repair needs --case --url --repo and GFA_TOKEN, --token-file, or --token");
  }
  const path = String(a.repo);
  if (!isGitRepo(path)) die(`${path}: not a git work tree`);
  if (git(path, ["rev-parse", "HEAD"]).code !== 0) die("HEAD is unreadable; cannot read-tree. Resolve object store first.");
  const name = basename(path);

  console.error(`Requesting repair authorization for '${name}' …`);
  const auth = await post(agentUrl(a.url, a.case, "/authorize-repair"), bearer, { repo: name });
  if (auth.status !== 200) die(`authorization refused (${auth.status}): ${JSON.stringify(auth.data)}`);
  const { token, evidenceId, exp } = auth.data;
  console.error(`✓ authorized against evidence ${evidenceId} (expires ${new Date(exp).toISOString()})`);
  console.error("\nPlanned action:  git -C " + path + " read-tree HEAD");
  console.error("This rebuilds .git/index from HEAD. Working tree is NOT touched. Evidence is preserved.\n");

  const ok = await confirm("Type 'yes' to execute the repair: ");
  if (!ok) {
    const declined = await post(agentUrl(a.url, a.case, "/repair-confirm"), bearer, {
      repo: name, token, executed: false, operator: collectorId(),
    });
    if (declined.status !== 200) {
      die(`repair declined, but audit recording failed (${declined.status}): ${JSON.stringify(declined.data)}`);
    }
    die("repair declined by operator (recorded).");
  }

  const r = git(path, ["read-tree", "HEAD"], { repair: true });
  const executed = r.code === 0;
  const recorded = await post(agentUrl(a.url, a.case, "/repair-confirm"), bearer, {
    repo: name, token, executed, operator: collectorId(),
  });
  if (!executed) die(`read-tree failed: ${r.stderr.trim()}`);
  if (recorded.status !== 200) {
    die(`index was rebuilt, but audit recording failed (${recorded.status}): ${JSON.stringify(recorded.data)}`);
  }
  console.log(`✓ index rebuilt from HEAD for '${name}'. Re-run scan to confirm the case is clean.`);
}

async function cmdDecrypt(a) {
  const token = resolveToken(a);
  if (!a.url || !token || !a.case || !a.id) {
    die("decrypt needs --case --url --id and GFA_TOKEN, --token-file, or --token");
  }
  const key = loadKey(a.key);
  if (!key) die("no content key (FORENSIC_CONTENT_KEY or --key) — cannot decrypt");
  const { status, data } = await get(agentUrl(a.url, a.case, `/evidence/${encodeURIComponent(a.id)}/sealed`), token);
  if (status !== 200) die(`fetch failed (${status}): ${JSON.stringify(data)}`);
  for (const s of data.sealed ?? []) {
    console.log(`\n──── ${s.label}  (${s.hash})\n`);
    try { console.log(unseal(key, s)); } catch (e) { console.error(`  ✗ decrypt failed: ${e.message}`); }
  }
}

function cmdKeygen() {
  const key = b64url(randomBytes(32));
  console.log(key);
  console.error("\nSave this somewhere only you control, e.g.:");
  console.error(`  mkdir -p ~/.forensic-agent && printf '%s' '${key}' > ~/.forensic-agent/content.key && chmod 600 ~/.forensic-agent/content.key`);
  console.error("Then pass it with:  --key ~/.forensic-agent/content.key   (or export FORENSIC_CONTENT_KEY=...)");
  console.error("The agent NEVER receives this key. Lose it and the sealed content is unrecoverable.");
}

function confirm(prompt) {
  return new Promise((resolve) => {
    process.stderr.write(prompt);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    process.stdin.once("data", (d) => {
      process.stdin.pause();
      resolve(String(d).trim().toLowerCase() === "yes");
    });
  });
}

// --- main ------------------------------------------------------------------
const argv = process.argv.slice(2);
const cmd = argv[0];
const a = parseArgs(argv.slice(1));
const run = {
  keygen: () => cmdKeygen(),
  scan: () => cmdScan(a),
  repair: () => cmdRepair(a),
  decrypt: () => cmdDecrypt(a),
}[cmd];

if (!run) {
  console.error("forensic-collect <keygen|scan|repair|decrypt> [options]");
  console.error("  see header of this file or collector/README.md for usage");
  process.exit(cmd ? 1 : 0);
}
await Promise.resolve(run()).catch((e) => die(e.message));
