/**
 * Authentication & chain-of-custody primitives, built on Web Crypto (available
 * in Workers — no Node crypto, no deps).
 *
 *  - constantTimeEqual:  timing-safe bearer-token comparison
 *  - signRepairToken / verifyRepairToken:  short-lived, HMAC-signed tokens that
 *    prove the agent authorized a `git read-tree HEAD` repair *after* evidence
 *    was preserved. The collector cannot forge one; the agent verifies its own
 *    signature when the collector confirms execution.
 */

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64urlFromBytes(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function bytesFromB64url(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256(s: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}

/**
 * Timing-safe equality. Both inputs are hashed to a fixed 32 bytes first so
 * neither length nor content leaks through comparison timing.
 */
export async function constantTimeEqual(a: string, b: string): Promise<boolean> {
  const [ha, hb] = await Promise.all([sha256(a), sha256(b)]);
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= ha[i]! ^ hb[i]!;
  return diff === 0;
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export interface RepairTokenPayload {
  caseId: string;
  repo: string;
  evidenceId: string;
  /** unique token id (also stored agent-side to bind authorize<->confirm). */
  jti: string;
  /** action this token authorizes — fixed for now. */
  action: "read-tree-head";
  /** epoch ms issued. */
  iat: number;
  /** epoch ms expiry. */
  exp: number;
}

/** Produce `<base64url(payload)>.<base64url(hmac)>`. */
export async function signRepairToken(
  secret: string,
  payload: RepairTokenPayload,
): Promise<string> {
  const body = b64urlFromBytes(enc.encode(JSON.stringify(payload)));
  const key = await hmacKey(secret);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(body)));
  return `${body}.${b64urlFromBytes(sig)}`;
}

export interface VerifyResult {
  valid: boolean;
  reason?: "malformed" | "bad-signature" | "expired";
  payload?: RepairTokenPayload;
}

/** Verify signature and expiry. Does not check evidence — caller does that. */
export async function verifyRepairToken(
  secret: string,
  token: string,
  now = Date.now(),
): Promise<VerifyResult> {
  const dot = token.indexOf(".");
  if (dot === -1) return { valid: false, reason: "malformed" };
  const body = token.slice(0, dot);
  const sigPart = token.slice(dot + 1);

  let sigOk: boolean;
  try {
    const key = await hmacKey(secret);
    sigOk = await crypto.subtle.verify(
      "HMAC",
      key,
      bytesFromB64url(sigPart),
      enc.encode(body),
    );
  } catch {
    return { valid: false, reason: "malformed" };
  }
  if (!sigOk) return { valid: false, reason: "bad-signature" };

  let payload: RepairTokenPayload;
  try {
    payload = JSON.parse(dec.decode(bytesFromB64url(body)));
  } catch {
    return { valid: false, reason: "malformed" };
  }
  if (typeof payload.exp !== "number" || payload.exp < now) {
    return { valid: false, reason: "expired", payload };
  }
  return { valid: true, payload };
}

/** Cheap random id (token jti / evidence id). */
export function randomId(prefix = ""): string {
  return prefix + b64urlFromBytes(crypto.getRandomValues(new Uint8Array(12)));
}
