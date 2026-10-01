/**
 * Shannon entropy over the character distribution of a string.
 * Used as a secondary signal for "this long random-looking token is probably
 * a credential" — regexes alone only catch well-known secret formats.
 */
export function shannonEntropy(text: string): number {
  if (text.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of text) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
