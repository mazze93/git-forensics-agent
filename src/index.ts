/**
 * Worker entry. Authenticates before any agent (Durable Object) is touched —
 * an unauthenticated request must never instantiate a case or trigger work.
 * Serves the static dashboard for everything else.
 */
import { routeAgentRequest } from "agents";
import type { Env } from "./env";
import { constantTimeEqual } from "./crypto";

// Re-export the DO class so the runtime can find it (wrangler `main`).
export { ForensicCaseAgent } from "./agent";

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "authorization,content-type",
};

function unauthorized(): Response {
  return new Response(JSON.stringify({ error: "unauthorized" }), {
    status: 401,
    headers: { "content-type": "application/json", ...CORS },
  });
}

/** Bearer check against INGEST_TOKEN, constant-time. Deny if misconfigured. */
async function authorized(request: Request, env: Env): Promise<boolean> {
  if (!env.INGEST_TOKEN) return false;
  const header = request.headers.get("authorization") ?? "";
  const m = header.match(/^Bearer\s+(.+)$/i);
  if (!m) return false;
  return constantTimeEqual(m[1]!, env.INGEST_TOKEN);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // Unauthenticated health probe.
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ ok: true, service: "git-forensics-agent" }), {
        headers: { "content-type": "application/json" },
      });
    }

    // Agent API — authenticated. Preflight first (carries no auth header).
    if (url.pathname.startsWith("/agents/")) {
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: CORS });
      }
      if (!(await authorized(request, env))) return unauthorized();

      const res = await routeAgentRequest(request, env, { cors: true });
      return res ?? new Response("Not found", { status: 404, headers: CORS });
    }

    // Everything else: static dashboard (Workers Assets).
    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
