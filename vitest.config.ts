import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
    // "forks" gives each test file its own process, so tests that change the
    // working directory (file-policy cases) cannot leak state into each other.
    pool: "forks",
  },
});
