import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import tls from 'node:tls';
import { decide, probe, type HelloOutcome } from './index.ts';
import type { HandshakeResult } from './handshake.ts';

const fx = (n: string) => fs.readFileSync(new URL(`../../test/fixtures/probe/${n}`, import.meta.url));
const closers: (() => void)[] = [];
after(() => closers.forEach((c) => c()));

async function listen(server: net.Server): Promise<number> {
  closers.push(() => server.close());
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  return (server.address() as net.AddressInfo).port;
}
async function tlsServer(opts: tls.TlsOptions): Promise<number> {
  const server = tls.createServer({ key: fx('key.pem'), cert: fx('cert.pem'), ...opts }, (s) => s.on('error', () => {}).end());
  server.on('tlsClientError', () => {});     // the probe hangs up mid-handshake on purpose
  return listen(server);
}
const run = (port: number) => probe({ host: '127.0.0.1', port, servername: 'localhost' }, { timeoutMs: 3000 });

test('server preferring a hybrid group: hybrid_selected', async () => {
  const r = await run(await tlsServer({ ecdhCurve: 'X25519MLKEM768:X25519:P-256' }));
  assert.equal(r.verdict, 'hybrid_selected');
  assert.equal(r.browser_offer.group?.name, 'X25519MLKEM768');
  assert.equal(r.browser_offer.tls_version, '1.3');
  assert.equal(r.reachable, true);
  assert.equal(r.handshakes.find((h) => h.group === 'X25519MLKEM768')?.completed, true);
  assert.ok(!r.evidence_notes.some((n) => n.startsWith('Disagreement')), r.evidence_notes.join('\n'));
});

test('classical first in the server list wins even without honorCipherOrder', async () => {
  /* Observed on OpenSSL 3.5.8: the ecdhCurve list acts as the server's group
     preference, so the browser-like offer gets x25519 although it lists the
     hybrid first. */
  const r = await run(await tlsServer({ ecdhCurve: 'X25519:P-256:X25519MLKEM768' }));
  assert.equal(r.browser_offer.group?.name, 'x25519');
  assert.equal(r.verdict, 'hybrid_supported_not_preferred');
});

test('server order honoured, classical first: hybrid_supported_not_preferred', async () => {
  const r = await run(await tlsServer({ ecdhCurve: 'X25519:P-256:X25519MLKEM768', honorCipherOrder: true }));
  assert.equal(r.browser_offer.group?.name, 'x25519');
  assert.equal(r.hybrid_only_offer.group?.name, 'X25519MLKEM768');
  assert.equal(r.verdict, 'hybrid_supported_not_preferred');
  assert.ok(!r.evidence_notes.some((n) => n.startsWith('Disagreement')), r.evidence_notes.join('\n'));
});

test('classical-only server: classical_only', async () => {
  const r = await run(await tlsServer({ ecdhCurve: 'X25519:P-256' }));
  assert.equal(r.verdict, 'classical_only');
  assert.equal(r.browser_offer.group?.name, 'x25519');
  assert.equal(r.hybrid_only_offer.outcome, 'alert');
  assert.equal(r.hybrid_only_offer.alert?.name, 'handshake_failure');
  assert.equal(r.handshakes.find((h) => h.group === 'X25519')?.completed, true);
  assert.ok(r.handshakes.filter((h) => h.group !== 'X25519').every((h) => !h.completed));
});

test('TLS 1.2-only server: tls_1_2_only with no group', async () => {
  const r = await run(await tlsServer({ maxVersion: 'TLSv1.2' }));
  assert.equal(r.verdict, 'tls_1_2_only');
  assert.equal(r.browser_offer.tls_version, '1.2');
  assert.equal(r.browser_offer.group, undefined);
});

test('server that closes at once: reachable but inconclusive', async () => {
  const r = await run(await listen(net.createServer((s) => s.destroy())));
  assert.equal(r.verdict, 'inconclusive');
  assert.equal(r.reachable, true);
  assert.equal(r.browser_offer.outcome, 'error');
  assert.match(r.evidence_notes.join('\n'), /Inconclusive/);
});

test('nothing listening: unreachable and inconclusive', async () => {
  const s = net.createServer();
  const port = await listen(s);
  await new Promise((r) => s.close(r));
  const r = await run(port);
  assert.equal(r.reachable, false);
  assert.equal(r.verdict, 'inconclusive');
});

test('server that never answers: timeout outcome', async () => {
  const r = await probe({ host: '127.0.0.1', port: await listen(net.createServer(() => {})), servername: 'localhost' }, { timeoutMs: 300 });
  assert.equal(r.browser_offer.outcome, 'timeout');
  assert.equal(r.verdict, 'inconclusive');
});

test('output never claims safety or compliance', async () => {
  const r = await run(await tlsServer({ ecdhCurve: 'X25519MLKEM768:X25519' }));
  assert.doesNotMatch(JSON.stringify(r), /\b(safe|compliant)\b/i);
});

const sh = (o: Partial<HelloOutcome>): HelloOutcome => ({ outcome: 'server_hello', tls_version: '1.3', ...o });
const hs = (group: string, completed: boolean, extra: Partial<HandshakeResult> = {}): HandshakeResult => ({ group, completed, ...extra });

test('decide: raw and Node disagreement is reported', () => {
  const d = decide(
    sh({ group: { code: 4588, name: 'X25519MLKEM768' } }),
    sh({ group: { code: 4588, name: 'X25519MLKEM768' } }),
    [hs('X25519MLKEM768', false, { error: 'boom' }), hs('X25519', true)],
  );
  assert.equal(d.verdict, 'hybrid_selected');
  assert.match(d.notes.join('\n'), /Disagreement/);
});

test('decide: a group Node cannot test is not read as server rejection', () => {
  const d = decide(
    sh({ group: { code: 29, name: 'x25519' } }),
    { outcome: 'alert', alert: { level: 2, description: 40, name: 'handshake_failure' } },
    [hs('SecP384r1MLKEM1024', false, { not_testable: true }), hs('X25519', true)],
  );
  assert.equal(d.verdict, 'classical_only');
  assert.ok(!d.notes.some((n) => n.startsWith('Disagreement')));
});

test('decide: a completed Node hybrid handshake alone upgrades classical to supported', () => {
  const d = decide(
    sh({ group: { code: 29, name: 'x25519' } }),
    { outcome: 'timeout' },
    [hs('SecP256r1MLKEM768', true), hs('X25519', true)],
  );
  assert.equal(d.verdict, 'hybrid_supported_not_preferred');
});

test('decide: classical with an unanswered hybrid-only offer stays inconclusive', () => {
  const d = decide(sh({ group: { code: 29, name: 'x25519' } }), { outcome: 'timeout' }, [hs('X25519', true)]);
  assert.equal(d.verdict, 'inconclusive');
});

/* Networked: AWS KMS documents X25519MLKEM768. */
const net_ = process.env.EDGEPQ_NET === '1';
test('kms.eu-west-2.amazonaws.com selects X25519MLKEM768', { skip: net_ ? false : 'set EDGEPQ_NET=1 to run' }, async () => {
  const r = await probe({ host: 'kms.eu-west-2.amazonaws.com' });
  assert.equal(r.verdict, 'hybrid_selected');
  assert.equal(r.browser_offer.group?.name, 'X25519MLKEM768');
});
