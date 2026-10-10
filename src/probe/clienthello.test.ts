import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildClientHello } from './clienthello.ts';

type Parsed = { suites: number[]; compression: number[]; sessionIdLen: number; exts: Map<number, Buffer>; order: number[] };

/* Test-only reader: walks the bytes the builder produced and checks every length. */
function parse(b: Buffer): Parsed {
  assert.equal(b.readUInt8(0), 0x16);
  assert.equal(b.readUInt16BE(1), 0x0301);
  assert.equal(b.readUInt16BE(3), b.length - 5, 'record length');
  assert.equal(b.readUInt8(5), 1, 'handshake type ClientHello');
  assert.equal(b.readUIntBE(6, 3), b.length - 9, 'handshake length');
  assert.equal(b.readUInt16BE(9), 0x0303);
  let p = 11 + 32;
  const sessionIdLen = b.readUInt8(p); p += 1 + sessionIdLen;
  const sl = b.readUInt16BE(p); p += 2;
  const suites: number[] = [];
  for (let i = 0; i < sl; i += 2) suites.push(b.readUInt16BE(p + i));
  p += sl;
  const cl = b.readUInt8(p); p += 1;
  const compression = [...b.subarray(p, p + cl)]; p += cl;
  const el = b.readUInt16BE(p); p += 2;
  assert.equal(p + el, b.length, 'extensions run to the end');
  const exts = new Map<number, Buffer>();
  const order: number[] = [];
  while (p < b.length) {
    const t = b.readUInt16BE(p);
    const l = b.readUInt16BE(p + 2);
    exts.set(t, b.subarray(p + 4, p + 4 + l));
    order.push(t);
    p += 4 + l;
  }
  assert.equal(p, b.length);
  return { suites, compression, sessionIdLen, exts, order };
}

const u16s = (b: Buffer, from = 2) => { const o: number[] = []; for (let i = from; i < b.length; i += 2) o.push(b.readUInt16BE(i)); return o; };

function shares(b: Buffer): { group: number; len: number; key: Buffer }[] {
  assert.equal(b.readUInt16BE(0), b.length - 2);
  const out = [];
  let p = 2;
  while (p < b.length) {
    const len = b.readUInt16BE(p + 2);
    out.push({ group: b.readUInt16BE(p), len, key: b.subarray(p + 4, p + 4 + len) });
    p += 4 + len;
  }
  return out;
}

test('browser hello: suites, compression, extension list and sni', () => {
  const { bytes, notes } = buildClientHello('example.com', 'browser');
  const h = parse(bytes);
  assert.deepEqual(h.suites, [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030]);
  assert.deepEqual(h.compression, [0]);
  assert.equal(h.sessionIdLen, 32);
  assert.deepEqual(h.order, [0, 10, 13, 43, 45, 51]);
  assert.equal(h.exts.get(0)!.subarray(5).toString('ascii'), 'example.com');
  assert.deepEqual(u16s(h.exts.get(13)!), [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]);
  assert.deepEqual([...h.exts.get(43)!], [4, 0x03, 0x04, 0x03, 0x03]);
  assert.deepEqual([...h.exts.get(45)!], [1, 1]);
  assert.match(notes.join(' '), /zero bytes/);
});

test('browser hello: group order and key share sizes', () => {
  const h = parse(buildClientHello('example.com', 'browser').bytes);
  assert.deepEqual(u16s(h.exts.get(10)!), [4588, 4587, 29, 23, 24]);
  const s = shares(h.exts.get(51)!);
  assert.deepEqual(s.map((x) => [x.group, x.len]), [[4588, 1216], [4587, 1249], [29, 32], [23, 65]]);
  /* X25519MLKEM768: ML-KEM key first, x25519 last. SecP256r1MLKEM768: point first. */
  assert.ok(s[0]!.key.subarray(0, 1184).every((v) => v === 0));
  assert.notDeepEqual(s[0]!.key.subarray(1184), Buffer.alloc(32));
  assert.equal(s[1]!.key[0], 0x04, 'uncompressed point marker leads the NIST hybrid');
});

test('hybrid-only hello offers three hybrids with two shares', () => {
  const h = parse(buildClientHello('example.com', 'hybrid_only').bytes);
  assert.deepEqual(u16s(h.exts.get(10)!), [4588, 4587, 4589]);
  assert.deepEqual(shares(h.exts.get(51)!).map((x) => x.group), [4588, 4587]);
});

test('an IP address is not sent as server_name', () => {
  const h = parse(buildClientHello('192.0.2.1', 'browser').bytes);
  assert.equal(h.exts.has(0), false);
});
