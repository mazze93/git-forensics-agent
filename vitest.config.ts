import { defineConfig } from "vitest/config";

// The analysis core is pure (no Workers runtime), so a plain Node environment
// is all the unit tests need. Agent/DO integration tests would use
// @cloudflare/vitest-pool-workers instead.
export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
  },
});
