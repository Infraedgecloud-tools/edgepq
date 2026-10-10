/* ============================================================================
   Read the server's first flight: a ServerHello, a HelloRetryRequest, or an
   alert. Records can arrive split across chunks, or several to a chunk, and a
   handshake message can span records. Everything after the first of those
   three is ignored.
   ========================================================================= */

export type Flight = {
  kind: 'server_hello' | 'hello_retry_request' | 'alert';
  tls_version?: string;
  cipher_suite?: number;
  group?: number;
  alert?: { level: number; description: number };
};
export type ParseState = { state: 'incomplete' } | { state: 'malformed'; reason: string } | { state: 'complete'; flight: Flight };

/* RFC 8446 section 4.1.3: SHA-256("HelloRetryRequest"). */
const HRR_RANDOM = 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c';

const VERSIONS: { [code: number]: string } = { 0x0304: '1.3', 0x0303: '1.2', 0x0302: '1.1', 0x0301: '1.0' };
const versionName = (v: number) => VERSIONS[v] ?? '0x' + v.toString(16).padStart(4, '0');

export function parseServerFlight(buf: Uint8Array): ParseState {
  const b = Buffer.from(buf);
  let pos = 0;
  let pending = Buffer.alloc(0);          // handshake bytes gathered across records
  while (pos < b.length) {
    if (b.length - pos < 5) return { state: 'incomplete' };
    const type = b.readUInt8(pos);
    const len = b.readUInt16BE(pos + 3);
    if (![20, 21, 22, 23].includes(type) || b.readUInt8(pos + 1) !== 3) {
      return { state: 'malformed', reason: `not a TLS record (first bytes ${b.subarray(pos, pos + 5).toString('hex')})` };
    }
    if (b.length - pos - 5 < len) return { state: 'incomplete' };
    const payload = b.subarray(pos + 5, pos + 5 + len);
    pos += 5 + len;
    if (type === 21) {
      if (payload.length < 2) return { state: 'malformed', reason: 'alert record shorter than 2 bytes' };
      return { state: 'complete', flight: { kind: 'alert', alert: { level: payload.readUInt8(0), description: payload.readUInt8(1) } } };
    }
    if (type !== 22) continue;            // change_cipher_spec and the like
    pending = Buffer.concat([pending, payload]);
    if (pending.length < 4) continue;
    const hsLen = pending.readUIntBE(1, 3);
    if (pending.length < 4 + hsLen) continue;
    if (pending.readUInt8(0) !== 2) return { state: 'malformed', reason: `first handshake message is type ${pending.readUInt8(0)}, not ServerHello` };
    return parseServerHello(pending.subarray(4, 4 + hsLen));
  }
  return { state: 'incomplete' };
}

function parseServerHello(body: Buffer): ParseState {
  try {
    let p = 0;
    const legacy = body.readUInt16BE(p); p += 2;
    const random = body.subarray(p, p + 32).toString('hex'); p += 32;
    p += 1 + body.readUInt8(p);           // legacy_session_id_echo
    const cipher = body.readUInt16BE(p); p += 3;   // suite, then compression method
    const flight: Flight = {
      kind: random === HRR_RANDOM ? 'hello_retry_request' : 'server_hello',
      tls_version: versionName(legacy),
      cipher_suite: cipher,
    };
    if (p < body.length) {
      const end = p + 2 + body.readUInt16BE(p); p += 2;
      if (end > body.length) return { state: 'malformed', reason: 'extensions overrun the ServerHello' };
      while (p + 4 <= end) {
        const t = body.readUInt16BE(p);
        const l = body.readUInt16BE(p + 2);
        const data = body.subarray(p + 4, p + 4 + l);
        p += 4 + l;
        if (t === 43 && data.length === 2) flight.tls_version = versionName(data.readUInt16BE(0));
        /* In a ServerHello key_share holds group + key; in an HRR only the group. */
        if (t === 51 && data.length >= 2) flight.group = data.readUInt16BE(0);
      }
    }
    return { state: 'complete', flight };
  } catch (e) {
    return { state: 'malformed', reason: `ServerHello did not parse: ${(e as Error).message}` };
  }
}
