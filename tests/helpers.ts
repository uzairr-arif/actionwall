/**
 * Shared test utilities.
 */

import { mkdtempSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { makeAction, type Action } from "../src/index.js";
import { defaultPolicy } from "../src/core/policy.js";
import type { PolicyDoc } from "../src/core/types.js";

export function shellAction(command: string, agentId = "test-agent"): Action {
  return makeAction({ tool: "shell", params: { command }, agentId });
}

export function toolAction(
  tool: string,
  params: Record<string, unknown>,
  context?: Action["context"]
): Action {
  return makeAction({ tool, params, agentId: "test-agent", context });
}

export function tmpDir(prefix = "actionwall-test-"): string {
  return mkdtempSync(path.join(os.tmpdir(), prefix));
}

/** Repo root captured at import time — chdir target before deleting temp dirs. */
export const REPO_ROOT = process.cwd();

/** Windows cannot delete a directory that is the process cwd; call before rmDir. */
export function restoreCwd(): void {
  try {
    process.chdir(REPO_ROOT);
  } catch {
    /* ignore */
  }
}

export function rmDir(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
}

export function makeFiles(dir: string, count: number, ext = "txt"): string[] {
  mkdirSync(dir, { recursive: true });
  const files: string[] = [];
  for (let i = 1; i <= count; i++) {
    const p = path.join(dir, `file-${String(i).padStart(2, "0")}.${ext}`);
    writeFileSync(p, "x");
    files.push(p);
  }
  return files;
}

export { defaultPolicy };
export type { PolicyDoc };
