/**
 * Worker bindings. Kept hand-written (rather than relying solely on
 * `wrangler types`) so `npm run typecheck` works on a clean checkout.
 * Run `npm run cf-typegen` to (re)generate `worker-configuration.d.ts` after
 * editing wrangler.jsonc.
 */
export interface Env {
  /** Durable Object namespace — binding name matches class so the routed URL
   *  segment is the documented `forensic-case-agent`. */
  ForensicCaseAgent: DurableObjectNamespace;
  /** Static dashboard assets. */
  ASSETS: Fetcher;
  /** Bearer the local collector must present to submit evidence (secret). */
  INGEST_TOKEN: string;
  /** HMAC key used to sign repair-authorization tokens (secret). */
  REPAIR_SIGNING_KEY: string;
}
