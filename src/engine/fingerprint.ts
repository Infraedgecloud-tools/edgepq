/* A finding's identity across runs: the rule and the resource, not the file.
   The id carries the file so two definitions of one address in two files
   stay distinct in a report; the fingerprint is what a suppression list, a
   ticket or a SARIF consumer keys on, and it survives a file being moved or
   renamed. FNV-1a, 64 bits, hex: no dependency, browser-safe, and nothing
   here needs to resist an adversary. */

const OFFSET = 0xcbf29ce484222325n;
const PRIME = 0x100000001b3n;

export function fnv1a64(text: string): string {
  let h = OFFSET;
  for (const byte of new TextEncoder().encode(text)) {
    h ^= BigInt(byte);
    h = BigInt.asUintN(64, h * PRIME);
  }
  return h.toString(16).padStart(16, '0');
}

export function fingerprint(ruleId: string, resourceType: string, address: string): string {
  return fnv1a64(`${ruleId}\u0000${resourceType}\u0000${address}`);
}
