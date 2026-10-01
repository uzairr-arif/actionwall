/**
 * Minimal ANSI coloring with automatic disabling when stdout is not a TTY
 * or NO_COLOR is set (https://no-color.org). Keeps the dependency tree at zero
 * for something this trivial.
 */

function enabled(): boolean {
  return Boolean(process.stdout.isTTY) && !process.env.NO_COLOR && !process.env.FORCE_COLOR?.startsWith("0");
}

function wrap(code: string, text: string): string {
  return enabled() ? `\x1b[${code}m${text}\x1b[0m` : text;
}

export const bold = (t: string) => wrap("1", t);
export const dim = (t: string) => wrap("2", t);
export const red = (t: string) => wrap("31", t);
export const green = (t: string) => wrap("32", t);
export const yellow = (t: string) => wrap("33", t);
export const blue = (t: string) => wrap("34", t);
export const magenta = (t: string) => wrap("35", t);
export const cyan = (t: string) => wrap("36", t);
