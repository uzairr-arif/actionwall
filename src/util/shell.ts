/**
 * A small, safe shell tokenizer. ActionWall never executes commands — it only
 * needs to split them the way a POSIX shell would so risk rules can inspect
 * the pieces. Heredocs, arithmetic and process substitution are treated as
 * opaque strings (and flagged as obfuscation by the command scanner).
 */

export interface ParsedCommand {
  /** The program name with any leading `VAR=x` assignments removed. */
  name: string;
  /** Arguments (quotes resolved), flags included verbatim. */
  args: string[];
  /** Full raw segment, for evidence. */
  raw: string;
}

/** Split a command line on top-level `&&`, `||`, `;` and `|` operators,
 * respecting single/double quotes. Returns the pipeline segments in order
 * plus the operators that joined them. */
export function splitSegments(command: string): { segments: string[]; operators: string[] } {
  const segments: string[] = [];
  const operators: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  let i = 0;

  const pushSegment = () => {
    if (current.trim().length > 0) segments.push(current.trim());
    current = "";
  };
  const pushOperator = (op: string) => {
    pushSegment();
    operators.push(op);
  };

  while (i < command.length) {
    const ch = command[i]!;
    if (quote) {
      current += ch;
      if (ch === quote) quote = null;
      i++;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
      i++;
      continue;
    }
    if (ch === "\\" && i + 1 < command.length) {
      current += ch + command[i + 1];
      i += 2;
      continue;
    }
    const two = command.slice(i, i + 2);
    if (two === "&&" || two === "||") {
      pushOperator(two);
      i += 2;
      continue;
    }
    if (ch === ";" || ch === "|") {
      pushOperator(ch);
      i++;
      continue;
    }
    current += ch;
    i++;
  }
  pushSegment();
  return { segments, operators };
}

/** Tokenize one segment into words the way a shell would (quote-aware). */
export function tokenize(segment: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  let i = 0;
  let started = false;

  while (i < segment.length) {
    const ch = segment[i]!;
    if (quote) {
      if (ch === quote) {
        quote = null; // closing quote: not part of the token
      } else {
        current += ch;
      }
      i++;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      started = true;
      i++;
      continue;
    }
    if (/\s/.test(ch)) {
      if (current.length > 0 || started) {
        tokens.push(current);
        current = "";
        started = false;
      }
      i++;
      continue;
    }
    current += ch;
    i++;
  }
  if (current.length > 0 || started) tokens.push(current);
  return tokens;
}

/** Parse a single segment into { name, args }, skipping `VAR=value` prefixes. */
export function parseCommand(segment: string): ParsedCommand | null {
  const tokens = tokenize(segment);
  let i = 0;
  while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i]!)) {
    i++; // environment assignment prefix: FOO=bar cmd ...
  }
  const rest = tokens.slice(i);
  if (rest.length === 0) return null;
  return { name: rest[0]!, args: rest.slice(1), raw: segment };
}

const FLAGS_WITH_VALUES = new Set(["-o", "-exec", "-name", "-if", "-of", "-size", "-e"]);

/** True when `args[index]` is a flag (not a positional target). */
export function isFlag(token: string, prev: string | undefined): boolean {
  if (token.startsWith("-") && token !== "-") {
    // Long options and clustered short flags are flags; a lone "-" is stdin.
    if (FLAGS_WITH_VALUES.has(token)) return true;
    return true;
  }
  if (prev !== undefined && FLAGS_WITH_VALUES.has(prev)) return true;
  return false;
}

/** Positional (non-flag) tokens of an arg list — usually the file targets. */
export function positionalArgs(args: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const tok = args[i]!;
    if (isFlag(tok, args[i - 1])) continue;
    // Skip a value that belongs to a value-taking flag.
    if (args[i - 1] !== undefined && FLAGS_WITH_VALUES.has(args[i - 1]!)) continue;
    out.push(tok);
  }
  return out;
}

/** Extract redirect targets (`> file`, `>> file`) from a raw segment. */
export function redirectTargets(segment: string): string[] {
  const tokens = tokenize(segment);
  const targets: string[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i]!;
    if (/^\d*>>?$/.test(tok) && tokens[i + 1] !== undefined) {
      targets.push(tokens[i + 1]!);
    }
  }
  return targets;
}
