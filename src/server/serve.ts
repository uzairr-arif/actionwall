/**
 * HTTP service mode: run ActionWall as a policy-check service.
 *
 *   GET  /healthz     → liveness + version
 *   POST /v1/check    → body: Action JSON → 200 { decision }
 *
 * Per-tenant policies: send `x-actionwall-tenant: <id>`; each tenant id maps
 * to its own loaded policy and engine. No header = the default policy.
 * Unknown tenant → 400. Malformed body → 400. Oversized body → 413.
 *
 * The server is a thin transport wrapper around the same ShieldEngine the CLI
 * uses: no extra dependencies (node:http), the engine never executes actions,
 * and a crash inside handling degrades to a 500 without leaking stack traces.
 */

import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createRequire } from "node:module";
import { parse as parseYaml } from "yaml";
import { ShieldEngine } from "../core/engine.js";
import { loadPolicy } from "../core/policy.js";
import type { Action, PolicyDoc } from "../core/types.js";

const require = createRequire(import.meta.url);
const { version: PACKAGE_VERSION } = require("../../package.json") as { version: string };

const MAX_BODY_BYTES = 1_000_000;

export interface ServeOptions {
  /** Default policy, used when no tenant header is present. */
  policy: PolicyDoc;
  /** Per-tenant policies, keyed by tenant id (from `x-actionwall-tenant`). */
  tenants?: Record<string, PolicyDoc>;
  /** Pass `false` to disable audit logging for every tenant (used by tests). */
  audit?: false;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(Object.assign(new Error("request body too large"), { code: "TOO_LARGE" }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: unknown, extraHeaders: Record<string, string> = {}): void {
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", ...extraHeaders });
  res.end(JSON.stringify(body));
}

function isValidAction(value: unknown): value is Action {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return typeof v.tool === "string" && v.tool.length > 0 && typeof v.params === "object" && v.params !== null;
}

async function handle(engines: Map<string, ShieldEngine>, defaultEngine: ShieldEngine, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = (req.url ?? "/").split("?")[0]!;

  if (req.method === "GET" && url === "/healthz") {
    sendJson(res, 200, { ok: true, name: "actionwall", version: PACKAGE_VERSION });
    return;
  }

  if (req.method !== "POST" || url !== "/v1/check") {
    if (url === "/v1/check") {
      sendJson(res, 405, { error: "method not allowed; use POST" });
      return;
    }
    sendJson(res, 404, { error: "not found; see POST /v1/check and GET /healthz" });
    return;
  }

  let engine = defaultEngine;
  const tenant = req.headers["x-actionwall-tenant"];
  if (tenant !== undefined) {
    const id = Array.isArray(tenant) ? tenant[0]! : tenant;
    const tenantEngine = engines.get(id);
    if (!tenantEngine) {
      sendJson(res, 400, { error: `unknown tenant "${id}"` });
      return;
    }
    engine = tenantEngine;
  }

  let raw: string;
  try {
    raw = await readBody(req);
  } catch (err) {
    sendJson(res, 413, { error: (err as { code?: string }).code === "TOO_LARGE" ? "request body too large" : "failed to read request body" });
    return;
  }

  let action: unknown;
  try {
    action = JSON.parse(raw || "{}");
  } catch {
    sendJson(res, 400, { error: "request body is not valid JSON" });
    return;
  }

  if (!isValidAction(action)) {
    sendJson(res, 400, { error: "body must be an Action: { tool: string, params: object, agentId?, context? }" });
    return;
  }

  const decision = engine.check(action);
  sendJson(res, 200, { decision }, {
    "x-actionwall-verdict": decision.verdict,
    "x-actionwall-risk": decision.risk,
  });
}

/**
 * Load a tenants file: a YAML document mapping tenant ids to policy file
 * paths, with an optional `default` entry used when no tenant header is sent.
 *
 *   default: policies/default.yaml
 *   tenants:
 *     ci-bot: policies/strict.yaml
 *     analyst: policies/readonly.yaml
 */
export function loadTenantsFile(path: string): { tenants: Record<string, PolicyDoc>; defaultPolicyPath?: string } {
  const data = parseYaml(readFileSync(path, "utf8")) as { default?: string; tenants?: Record<string, string> };
  const tenants: Record<string, PolicyDoc> = {};
  for (const [id, file] of Object.entries(data.tenants ?? {})) {
    tenants[id] = loadPolicy(file);
  }
  return { tenants, defaultPolicyPath: data.default };
}

/** Create the HTTP server. Call `server.listen(port, host)` to start it. */
export function createActionWallServer(options: ServeOptions): Server {  const engineOptions = options.audit === false ? { audit: false as const } : {};
  const defaultEngine = new ShieldEngine(options.policy, engineOptions);
  const engines = new Map<string, ShieldEngine>();
  if (options.tenants) {
    for (const [id, policy] of Object.entries(options.tenants)) {
      engines.set(id, new ShieldEngine(policy, engineOptions));
    }
  }

  return createServer((req, res) => {
    void handle(engines, defaultEngine, req, res).catch(() => {
      if (!res.headersSent) {
        sendJson(res, 500, { error: "internal error while evaluating the action" });
      } else {
        res.end();
      }
    });
  });
}
