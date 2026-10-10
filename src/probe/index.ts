/* ============================================================================
   Evidence of what key exchange a TLS endpoint actually negotiates.

   A report that a listener policy contains PQ is an inference. A report that
   the server selected X25519MLKEM768 when offered it, on a stated date, is
   evidence. Two independent techniques, both reported: a hand-built
   ClientHello read at the byte level, and handshakes through Node's TLS stack.
   A disagreement between them is reported, never hidden.

   Node-only (node:net, node:tls, node:crypto). Nothing else may import this.
   ========================================================================= */

import net from 'node:net';
import { buildClientHello, type OfferKind } from './clienthello.ts';
import { HANDSHAKE_GROUPS, tryHandshake, type HandshakeResult } from './handshake.ts';
import { alertName, cipherName, groupName, isHybrid } from './groups.ts';
import { parseServerFlight, type Flight } from './serverhello.ts';

export type HelloOutcome = {
  outcome: 'server_hello' | 'hello_retry_request' | 'alert' | 'timeout' | 'error';
  tls_version?: '1.3' | '1.2' | string;
  group?: { code: number; name: string };
  cipher_suite?: { code: number; name: string };
  alert?: { level: number; description: number; name: string };
  error?: string;
};

export type Verdict = 'hybrid_selected' | 'hybrid_supported_not_preferred' | 'classical_only' | 'tls_1_2_only' | 'inconclusive';

export type ProbeResult = {
  target: { host: string; port: number; servername: string };
  probed_at: string;
  reachable: boolean;
  browser_offer: HelloOutcome;
  hybrid_only_offer: HelloOutcome;
  handshakes: HandshakeResult[];
  verdict: Verdict;
  evidence_notes: string[];
};

type Exchange = { connected: boolean; result: HelloOutcome };

const describe = (f: Flight): HelloOutcome => ({
  outcome: f.kind,
  ...(f.tls_version !== undefined ? { tls_version: f.tls_version } : {}),
  ...(f.group !== undefined ? { group: { code: f.group, name: groupName(f.group) } } : {}),
  ...(f.cipher_suite !== undefined ? { cipher_suite: { code: f.cipher_suite, name: cipherName(f.cipher_suite) } } : {}),
  ...(f.alert ? { alert: { ...f.alert, name: alertName(f.alert.description) } } : {}),
});

/* Send one ClientHello, read until the first ServerHello, HRR or alert, hang up. */
function exchange(host: string, port: number, hello: Buffer, timeoutMs: number): Promise<Exchange> {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    let connected = false;
    let done = false;
    let received = Buffer.alloc(0);
    const finish = (result: HelloOutcome) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve({ connected, result });
    };
    socket.setTimeout(timeoutMs, () => finish({ outcome: 'timeout', error: `no ServerHello within ${timeoutMs} ms` }));
    socket.once('connect', () => { connected = true; socket.write(hello); });
    socket.on('data', (chunk) => {
      received = Buffer.concat([received, chunk]);
      const parsed = parseServerFlight(received);
      if (parsed.state === 'complete') finish(describe(parsed.flight));
      else if (parsed.state === 'malformed') finish({ outcome: 'error', error: parsed.reason });
    });
    socket.once('error', (e: NodeJS.ErrnoException) => finish({ outcome: 'error', error: e.code ? `${e.code}: ${e.message}` : e.message }));
    socket.once('close', () => finish({ outcome: 'error', error: `connection closed after ${received.length} bytes, before a ServerHello` }));
  });
}

const speaks13 = (o: HelloOutcome) => (o.outcome === 'server_hello' || o.outcome === 'hello_retry_request') && o.tls_version === '1.3';
const hybridNamed = (o: HelloOutcome) => o.group !== undefined && isHybrid(o.group.code);

/* Pure: the verdict rules and the A-versus-B cross-check. */
export function decide(browser: HelloOutcome, hybridOnly: HelloOutcome, handshakes: HandshakeResult[]): { verdict: Verdict; notes: string[] } {
  const notes: string[] = [];
  const hybridDone = handshakes.filter((h) => h.completed && h.group !== 'X25519');
  const x25519 = handshakes.find((h) => h.group === 'X25519');

  /* Cross-check: the hand-built hello against Node's own handshakes. */
  if (hybridNamed(browser) && browser.outcome === 'server_hello') {
    const own = handshakes.find((h) => h.group === browser.group?.name);
    if (own && !own.not_testable && !own.completed) notes.push(`Disagreement: the raw hello got ${browser.group?.name} selected, but a Node handshake restricted to it failed (${own.error ?? 'no detail'}).`);
  }
  if (hybridOnly.outcome === 'alert' && hybridDone.length > 0) notes.push(`Disagreement: the hybrid-only raw hello drew an alert (${hybridOnly.alert?.name}), but Node completed a handshake with ${hybridDone.map((h) => h.group).join(', ')}.`);
  if (hybridNamed(hybridOnly) && handshakes.length > 0 && handshakes.every((h) => h.group === 'X25519' || h.not_testable || !h.completed) && handshakes.some((h) => h.group !== 'X25519' && !h.not_testable)) {
    notes.push(`Disagreement: the hybrid-only raw hello got ${hybridOnly.group?.name} selected, but no Node hybrid handshake completed.`);
  }
  if (speaks13(browser) && x25519 && !x25519.completed && !x25519.not_testable) notes.push(`Disagreement: the raw hello negotiated TLS 1.3, but a Node x25519 handshake failed (${x25519.error ?? 'no detail'}).`);

  if (browser.outcome === 'server_hello' && hybridNamed(browser)) return { verdict: 'hybrid_selected', notes };
  const hybridSeen = hybridNamed(hybridOnly) || hybridDone.length > 0 || hybridNamed(browser);
  if (speaks13(browser) && hybridSeen) return { verdict: 'hybrid_supported_not_preferred', notes };
  if (browser.outcome === 'server_hello' && browser.tls_version === '1.2') return { verdict: 'tls_1_2_only', notes };
  const hybridAnswered = hybridOnly.outcome === 'server_hello' || hybridOnly.outcome === 'hello_retry_request' || hybridOnly.outcome === 'alert';
  if (speaks13(browser) && hybridAnswered) return { verdict: 'classical_only', notes };

  notes.push(`Inconclusive: browser-like offer ended in ${browser.outcome}${browser.error ? ` (${browser.error})` : ''}; hybrid-only offer ended in ${hybridOnly.outcome}${hybridOnly.error ? ` (${hybridOnly.error})` : ''}.`);
  return { verdict: 'inconclusive', notes };
}

export async function probe(
  target: { host: string; port?: number; servername?: string },
  opts: { timeoutMs?: number } = {},
): Promise<ProbeResult> {
  const timeoutMs = opts.timeoutMs ?? 5000;
  const port = target.port ?? 443;
  const servername = target.servername ?? target.host;
  const probedAt = new Date().toISOString();

  const run = (kind: OfferKind) => {
    const hello = buildClientHello(servername, kind);
    return exchange(target.host, port, hello.bytes, timeoutMs).then((x) => ({ ...x, notes: hello.notes }));
  };
  const browser = await run('browser');
  const hybridOnly = await run('hybrid_only');
  const handshakes: HandshakeResult[] = [];
  for (const g of HANDSHAKE_GROUPS) handshakes.push(await tryHandshake(target.host, port, servername, g, timeoutMs));

  const { verdict, notes } = decide(browser.result, hybridOnly.result, handshakes);
  for (const h of handshakes) if (h.not_testable) notes.push(`${h.group} is not testable on this Node (OpenSSL refused the group name).`);
  return {
    target: { host: target.host, port, servername },
    probed_at: probedAt,
    reachable: browser.connected || hybridOnly.connected || handshakes.some((h) => h.completed),
    browser_offer: browser.result,
    hybrid_only_offer: hybridOnly.result,
    handshakes,
    verdict,
    evidence_notes: [...browser.notes, ...notes],
  };
}
