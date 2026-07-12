import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  signRepairToken,
  verifyRepairToken,
  type RepairTokenPayload,
} from "../src/crypto";

const payload = (overrides: Partial<RepairTokenPayload> = {}): RepairTokenPayload => ({
  caseId: "incident-1",
  repo: "secure-pride",
  evidenceId: "ev_1",
  jti: "jti_1",
  action: "read-tree-head",
  iat: 1_000,
  exp: 2_000,
  ...overrides,
});

describe("repair authorization tokens", () => {
  it("accepts a valid token before expiry", async () => {
    const token = await signRepairToken("secret-a", payload());
    const result = await verifyRepairToken("secret-a", token, 1_500);
    expect(result).toMatchObject({ valid: true, payload: payload() });
  });

  it("rejects the wrong key, malformed input, and expired tokens", async () => {
    const token = await signRepairToken("secret-a", payload());
    await expect(verifyRepairToken("secret-b", token, 1_500)).resolves.toMatchObject({
      valid: false,
      reason: "bad-signature",
    });
    await expect(verifyRepairToken("secret-a", "not-a-token", 1_500)).resolves.toMatchObject({
      valid: false,
      reason: "malformed",
    });
    await expect(verifyRepairToken("secret-a", token, 2_001)).resolves.toMatchObject({
      valid: false,
      reason: "expired",
    });
  });
});

describe("credential handling", () => {
  it("never persists the dashboard bearer in sessionStorage", () => {
    const dashboard = readFileSync(new URL("../public/index.html", import.meta.url), "utf8");
    expect(dashboard).toContain('JSON.stringify({ url, caseId })');
    expect(dashboard).not.toContain('sessionStorage.setItem("gfa", JSON.stringify(cfg()))');
    expect(dashboard).not.toContain("saved.token");
  });

  it("rejects collector content keys that are not 32 bytes", () => {
    const collector = new URL("../collector/forensic-collect.mjs", import.meta.url);
    const run = spawnSync(
      process.execPath,
      [
        collector.pathname,
        "scan",
        "--case",
        "x",
        "--url",
        "https://example.invalid",
        "--token",
        "x",
        "--repos",
        "/tmp",
        "--key",
        "bad",
      ],
      { encoding: "utf8" },
    );
    expect(run.status).toBe(1);
    expect(run.stderr).toContain("content key must decode to exactly 32 bytes");
  });
});
