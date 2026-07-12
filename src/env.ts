/**
 * Bindings generated from wrangler.jsonc, extended only with secrets because
 * Wrangler deliberately cannot infer secret names from configuration.
 */
export interface Env extends Cloudflare.Env {
  /** Bearer the local collector must present to submit evidence (secret). */
  INGEST_TOKEN: string;
  /** HMAC key used to sign repair-authorization tokens (secret). */
  REPAIR_SIGNING_KEY: string;
}
