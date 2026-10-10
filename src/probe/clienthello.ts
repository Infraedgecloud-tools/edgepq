/* ============================================================================
   A TLS 1.3 ClientHello built by hand, shaped like a current browser's.

   Two offers: `browser` (hybrid first, classical behind it) and `hybrid_only`
   (the three hybrid groups, to learn whether the server speaks any of them
   when it would rather not). The handshake is never completed.
   ========================================================================= */

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import {
  SECP256R1, SECP256R1MLKEM768, SECP384R1, SECP384R1MLKEM1024, X25519, X25519MLKEM768,
} from './groups.ts';

export type OfferKind = 'browser' | 'hybrid_only';
export type BuiltHello = { bytes: Buffer; notes: string[] };

const u8 = (n: number) => Buffer.from([n]);
const u16 = (n: number) => Buffer.from([n >> 8, n & 0xff]);
const u24 = (n: number) => Buffer.from([n >> 16, (n >> 8) & 0xff, n & 0xff]);
const vec8 = (b: Buffer) => Buffer.concat([u8(b.length), b]);
const vec16 = (b: Buffer) => Buffer.concat([u16(b.length), b]);
const list16 = (codes: number[]) => vec16(Buffer.concat(codes.map(u16)));
const ext = (type: number, body: Buffer) => Buffer.concat([u16(type), vec16(body)]);

const CIPHER_SUITES = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030];
const SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];
const BROWSER_GROUPS = [X25519MLKEM768, SECP256R1MLKEM768, X25519, SECP256R1, SECP384R1];
const HYBRID_ONLY_GROUPS = [X25519MLKEM768, SECP256R1MLKEM768, SECP384R1MLKEM1024];
const MLKEM768_EK_BYTES = 1184;

const x25519Public = (): Buffer => {
  const der = generateKeyPairSync('x25519').publicKey.export({ type: 'spki', format: 'der' });
  return der.subarray(der.length - 32);
};
const p256Public = (): Buffer => {
  const der = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'der' });
  return der.subarray(der.length - 65);
};

/* Node 22.23 has no 'ml-kem-768' key type (generateKeyPairSync throws), so
   the encapsulation key is 1184 zero bytes. FIPS 203 only asks a server to
   check that every 12-bit coefficient is below q = 3329 and that the key
   re-encodes to itself; zeros pass. Servers choose the group before they use
   the key, so a ServerHello naming the group is still proof of selection. */
const mlkem768Public = (): Buffer => Buffer.alloc(MLKEM768_EK_BYTES);

/* Share layouts: draft-ietf-tls-ecdhe-mlkem-04 section 3,
   https://www.ietf.org/archive/id/draft-ietf-tls-ecdhe-mlkem-04.html
   X25519MLKEM768 puts the ML-KEM key first; SecP256r1MLKEM768 puts the
   ECDH point first. */
const shareFor = (group: number): Buffer => {
  switch (group) {
    case X25519: return x25519Public();
    case SECP256R1: return p256Public();
    case X25519MLKEM768: return Buffer.concat([mlkem768Public(), x25519Public()]);
    case SECP256R1MLKEM768: return Buffer.concat([p256Public(), mlkem768Public()]);
    default: throw new Error(`no key share for group ${group}`);
  }
};

export function buildClientHello(serverName: string, kind: OfferKind): BuiltHello {
  const groups = kind === 'browser' ? BROWSER_GROUPS : HYBRID_ONLY_GROUPS;
  const shared = groups.slice(0, kind === 'browser' ? 4 : 2);
  const shares = Buffer.concat(shared.map((g) => {
    const key = shareFor(g);
    return Buffer.concat([u16(g), vec16(key)]);
  }));
  /* RFC 6066: literal IP addresses are not sent as server_name. */
  const sni = isIP(serverName) ? [] : [ext(0, vec16(Buffer.concat([u8(0), vec16(Buffer.from(serverName, 'ascii'))])))];
  const extensions = Buffer.concat([
    ...sni,
    ext(10, list16(groups)),
    ext(13, list16(SIG_ALGS)),
    ext(43, vec8(Buffer.concat([u16(0x0304), u16(0x0303)]))),
    ext(45, vec8(u8(1))),
    ext(51, vec16(shares)),
  ]);
  const body = Buffer.concat([
    u16(0x0303), randomBytes(32), vec8(randomBytes(32)),
    list16(CIPHER_SUITES), vec8(u8(0)), vec16(extensions),
  ]);
  const handshake = Buffer.concat([u8(1), u24(body.length), body]);
  return {
    bytes: Buffer.concat([u8(0x16), u16(0x0301), vec16(handshake)]),
    notes: ['ML-KEM-768 encapsulation key sent as 1184 zero bytes (this Node cannot generate one); the server named its group before using it'],
  };
}
