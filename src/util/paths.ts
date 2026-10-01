/**
 * Path helpers: home expansion, POSIX normalization, glob matching and a
 * bounded filesystem counter used by the bulk-delete rule.
 *
 * All matching is done on POSIX-style absolute paths with any Windows drive
 * prefix ("C:") stripped, so policies written as "/etc/**" or ".env" match
 * identically on Linux, macOS and Windows.
 */

import { homedir } from "node:os";
import * as fs from "node:fs";
import * as path from "node:path";

/** Hard caps so a pathological glob can never make the scanner hang. */
export const WALK_MAX_ENTRIES = 5000;
export const WALK_MAX_DEPTH = 12;

export function expandHome(p: string): string {
  if (p === "~") return homedir();
  if (p.startsWith("~/") || p.startsWith("~\\")) {
    return path.join(homedir(), p.slice(2));
  }
  return p;
}

/** Absolute, normalized, POSIX-flavored path (drive prefix stripped on Windows). */
export function normalizePath(p: string, cwd: string = process.cwd()): string {
  const expanded = expandHome(p);
  const resolved = path.isAbsolute(expanded) ? expanded : path.resolve(cwd, expanded);
  return stripDrive(path.normalize(resolved).replace(/\\/g, "/"));
}

/** Remove a leading "C:" style drive prefix, leaving "/foo/bar". */
export function stripDrive(p: string): string {
  return p.replace(/^[A-Za-z]:/, "");
}

/**
 * Glob → RegExp. Semantics kept intentionally small:
 *   `**` matches any number of path segments (including none, and `/`)
 *   `*`  matches any characters except `/`
 *   `?`  matches a single character except `/`
 * Everything else is literal.
 */
export function globToRegExp(pattern: string): RegExp {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i]!;
    if (ch === "*") {
      if (pattern[i + 1] === "*") {
        // Consume the whole "**" (or "**/") run as "any segments".
        re += ".*";
        i++;
        if (pattern[i + 1] === "/") i++; // "**/" also matches zero segments
      } else {
        re += "[^/]*";
      }
    } else if (ch === "?") {
      re += "[^/]";
    } else if ("\\^$.|+()[]{}".includes(ch)) {
      re += `\\${ch}`;
    } else {
      re += ch;
    }
  }
  return new RegExp(`^${re}$`);
}

/** True when `p` (already normalized) matches a policy glob pattern. */
export function pathMatches(pattern: string, p: string): boolean {
  const normPattern = stripDrive(expandHome(pattern).replace(/\\/g, "/"));
  if (globToRegExp(normPattern).test(p)) return true;
  // Convenience: a pattern like ".env" or "secrets/**" written without a
  // leading "**/" should match the file at any depth.
  if (!normPattern.startsWith("/") && !normPattern.startsWith("**")) {
    return globToRegExp(`**/${normPattern}`).test(p);
  }
  return false;
}

const GLOB_CHARS = /[*?[\]]/;

export function hasGlobChars(p: string): boolean {
  return GLOB_CHARS.test(p);
}

export interface CountResult {
  /** Number of files that would be removed (directories count their contents). */
  files: number;
  /** True when the walk hit its safety cap and the number is a lower bound. */
  capped: boolean;
}

/**
 * Count the real files a delete of `targets` would touch, expanding globs and
 * recursing into directories. Read-only and strictly bounded.
 */
export function countDeletableFiles(targets: string[], cwd: string = process.cwd()): CountResult {
  let files = 0;
  let capped = false;

  const bump = (n: number) => {
    files += n;
    if (files >= WALK_MAX_ENTRIES) capped = true;
    files = Math.min(files, WALK_MAX_ENTRIES);
  };

  for (const raw of targets) {
    if (capped) break;
    const norm = expandHome(raw);
    const abs = path.isAbsolute(norm) ? norm : path.resolve(cwd, norm);

    if (hasGlobChars(abs)) {
      const dirPart = path.dirname(abs);
      const base = path.basename(abs);
      const baseRe = globToRegExp(base);
      let entries: fs.Dirent[];
      try {
        entries = fs.readdirSync(dirPart, { withFileTypes: true });
      } catch {
        continue; // directory does not exist → glob matches nothing
      }
      for (const entry of entries) {
        if (capped) break;
        if (!baseRe.test(entry.name)) continue;
        const full = path.join(dirPart, entry.name);
        if (entry.isDirectory()) {
          const sub = countDir(full, 1);
          bump(sub.files);
          capped = capped || sub.capped;
        } else {
          bump(1);
        }
      }
    } else {
      let stat: fs.Stats;
      try {
        stat = fs.statSync(abs);
      } catch {
        continue; // nothing to delete
      }
      if (stat.isDirectory()) {
        const sub = countDir(abs, 1);
        bump(sub.files);
        capped = capped || sub.capped;
      } else {
        bump(1);
      }
    }
  }

  return { files, capped };
}

/** Recursively count files inside `dir`, bounded. */
function countDir(dir: string, depth: number): CountResult {
  if (depth > WALK_MAX_DEPTH) return { files: 0, capped: true };
  let files = 0;
  let capped = false;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return { files: 0, capped: false };
  }
  for (const entry of entries) {
    if (files >= WALK_MAX_ENTRIES) {
      capped = true;
      break;
    }
    if (entry.isDirectory()) {
      const sub = countDir(path.join(dir, entry.name), depth + 1);
      files += sub.files;
      capped = capped || sub.capped;
    } else {
      files += 1;
    }
    files = Math.min(files, WALK_MAX_ENTRIES);
  }
  return { files, capped };
}

/**
 * True for delete targets that mean "the whole machine / home / current tree":
 * "/", "/*", "~", "~/*", "$HOME", ".", "..", "*", a bare drive root, etc.
 */
export function isRootishTarget(target: string): boolean {
  const t = target.trim();
  if (["/", "/*", ".", "..", "./*", "../*", "*", "~", "~/*", "$HOME", "$HOME/*"].includes(t)) {
    return true;
  }
  if (/^[A-Za-z]:\\?\*?$/.test(t)) return true; // "C:\", "C:\*", "C:"
  return false;
}
