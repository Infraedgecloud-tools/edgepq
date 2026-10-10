import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseServerFlight } from './serverhello.ts';

const u16 = (n: number) => Buffer.from([n >> 8, n & 0xff]);
const record = (type: number, payload: Buffer) => Buffer.concat([Buffer.from([type, 3, 3]), u16(payload.length), payload]);
const HRR = Buffer.from('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c', 'hex');

function serverHello(opts: { random?: Buffer; cipher?: number; group?: number; hrr?: boolean; v13?: boolean }): Buffer {
  const exts: Buffer[] = [];
  if (opts.v13) exts.push(Buffer.concat([u16(43), u16(2), u16(0x0304)]));
  if (opts.group !== undefined) {
    const data = opts.hrr ? u16(opts.group) : Buffer.concat([u16(opts.group), u16(4), Buffer.alloc(4, 7)]);
    exts.push(Buffer.concat([u16(51), u16(data.length), data]));
  }
  const e = Buffer.concat(exts);
  const body = Buffer.concat([u16(0x0303), opts.random ?? Buffer.alloc(32, 1), Buffer.from([0]), u16(opts.cipher ?? 0x1302), Buffer.from([0]), ...(exts.length ? [u16(e.length), e] : [])]);
  return Buffer.concat([Buffer.from([2, 0, body.length >> 8, body.length & 0xff]), body]);
}

test('TLS 1.3 ServerHello: version, cipher and selected group', () => {
  const r = parseServerFlight(record(22, serverHello({ v13: true, group: 4588 })));
  assert.deepEqual(r, { state: 'complete', flight: { kind: 'server_hello', tls_version: '1.3', cipher_suite: 0x1302, group: 4588 } });
});

test('TLS 1.2 ServerHello has no group and reports 1.2', () => {
  const r = parseServerFlight(record(22, serverHello({ cipher: 0xc02b })));
  assert.deepEqual(r, { state: 'complete', flight: { kind: 'server_hello', tls_version: '1.2', cipher_suite: 0xc02b } });
});

test('HelloRetryRequest is recognised by its fixed random', () => {
  const r = parseServerFlight(record(22, serverHello({ random: HRR, v13: true, group: 23, hrr: true })));
  assert.equal(r.state, 'complete');
  assert.deepEqual(r.state === 'complete' && r.flight, { kind: 'hello_retry_request', tls_version: '1.3', cipher_suite: 0x1302, group: 23 });
});

test('alert record', () => {
  const r = parseServerFlight(record(21, Buffer.from([2, 40])));
  assert.deepEqual(r, { state: 'complete', flight: { kind: 'alert', alert: { level: 2, description: 40 } } });
});

test('a ServerHello split across chunks and records', () => {
  const hs = serverHello({ v13: true, group: 29 });
  const whole = Buffer.concat([record(22, hs.subarray(0, 10)), record(22, hs.subarray(10))]);
  for (let cut = 1; cut < whole.length; cut++) {
    assert.equal(parseServerFlight(whole.subarray(0, cut)).state, 'incomplete', `cut at ${cut}`);
  }
  const r = parseServerFlight(whole);
  assert.equal(r.state === 'complete' && r.flight.group, 29);
});

test('only the first message counts when several records share a chunk', () => {
  const chunk = Buffer.concat([record(22, serverHello({ v13: true, group: 29 })), record(20, Buffer.from([1])), record(23, Buffer.alloc(40))]);
  const r = parseServerFlight(chunk);
  assert.equal(r.state === 'complete' && r.flight.kind, 'server_hello');
  const lead = Buffer.concat([record(20, Buffer.from([1])), record(21, Buffer.from([1, 0]))]);
  assert.equal(parseServerFlight(lead).state === 'complete' && (parseServerFlight(lead) as any).flight.kind, 'alert');
});

test('non-TLS bytes are malformed, not incomplete', () => {
  const r = parseServerFlight(Buffer.from('HTTP/1.1 400 Bad Request\r\n'));
  assert.equal(r.state, 'malformed');
});

test('a hello that is not a ServerHello is malformed', () => {
  const r = parseServerFlight(record(22, Buffer.from([1, 0, 0, 1, 0])));
  assert.equal(r.state, 'malformed');
});
