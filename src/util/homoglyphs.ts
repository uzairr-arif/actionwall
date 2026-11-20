/**
 * Homoglyph and mixed-script detection.
 *
 * Attackers swap Latin characters with lookalikes from other scripts
 * (Cyrillic "а" U+0430, Greek "ο" U+03BF, and friends) so that malicious
 * text looks harmless to a reviewer while reading differently to the model.
 *
 * Detection rule: a word that MIXES ordinary Latin letters with known
 * confusable lookalikes is flagged. Pure non-Latin text (someone writing
 * Russian or Greek on purpose) never triggers, which keeps the false-positive
 * rate near zero for international users.
 */

/** Common lookalikes that map onto Latin letters. Far from exhaustive:
 * covers the characters seen in real evasion attempts (brand and command
 * impersonation) without dragging in whole Unicode tables. */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
  "\u0443": "y", "\u0445": "x", "\u0432": "b", "\u043d": "h", "\u043a": "k",
  "\u043c": "m", "\u0442": "t", "\u0438": "i", "\u0456": "i", "\u0455": "s",
  // Greek
  "\u03bf": "o", "\u03b1": "a", "\u03b5": "e", "\u03c1": "p", "\u03bd": "n",
  "\u03ba": "k", "\u03c4": "t", "\u03c5": "u", "\u03b9": "i", "\u03c7": "x",
  // Armenian and fullwidth lookalikes seen in the wild
  "\u0561": "a", "\u0575": "y", "\u0585": "o", "\uFF41": "a", "\uFF4F": "o",
  "\uFF50": "p", "\uFF52": "r", "\uFF43": "c", "\uFF53": "s",
};

export interface ConfusableHit {
  /** The lookalike character itself. */
  char: string;
  /** The Latin letter it impersonates. */
  latin: string;
  /** Position in the inspected text. */
  index: number;
}

export interface ConfusableScan {
  /** Lookalike characters found, in order. */
  hits: ConfusableHit[];
  /** True when at least one word mixes Latin letters with lookalikes,
   * which is the actual evasion signal. */
  mixedScriptWordFound: boolean;
  /** First mixed word, for evidence. */
  example?: string;
}

/** Scan text for homoglyph evasion. Only mixed-script words count. */
export function scanConfusables(text: string): ConfusableScan {
  const hits: ConfusableHit[] = [];
  for (let i = 0; i < text.length; i++) {
    const mapped = CONFUSABLES[text[i]!];
    if (mapped) hits.push({ char: text[i]!, latin: mapped, index: i });
  }

  let mixedScriptWordFound = false;
  let example: string | undefined;
  // Split into letter runs so we can inspect each word in isolation.
  const words = text.match(/[\p{L}\p{N}]+/gu) ?? [];
  for (const word of words) {
    let latin = 0;
    let lookalike = 0;
    for (const ch of word) {
      if (CONFUSABLES[ch]) lookalike++;
      else if (/[a-zA-Z]/.test(ch)) latin++;
    }
    if (latin > 0 && lookalike > 0) {
      mixedScriptWordFound = true;
      example ??= word;
    }
  }

  return { hits, mixedScriptWordFound, example };
}
