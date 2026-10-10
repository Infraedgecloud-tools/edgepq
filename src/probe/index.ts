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
import { CLASSICAL_GROUPS, HANDSHAKE_GROUPS, tryHandshake, type HandshakeResult } from './handshake.ts';
import { alertName, cipherName, groupName, isHybrid, isPureMlkem } from './groups.ts';
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

/* Pure: the verdict rules.

   Evidence, in order of authority:
     1. Node's own handshakes restricted to one group, with real keys, where
        this Node could run them ("testable");
     2. the hand-built hellos, whose ML-KEM share is a placeholder: they show
        what the server *selects* when offered a browser-like list, but a
        server that validates shares before choosing can only refuse them.

   With testable hybrid handshakes:
     some completed  + raw hello selected a hybrid     -> hybrid_selected
     some completed  + raw hello classical TLS 1.3     -> hybrid_supported_not_preferred
     some completed  + raw hello anything else         -> hybrid_supported_not_preferred (noted)
     none completed  + raw hello selected a hybrid     -> inconclusive (disagreement)
     none completed  + raw hello classical TLS 1.3     -> classical_only
     none completed  + raw hello TLS 1.2               -> tls_1_2_only
   Without them (older Node): the raw hellos alone, and an alert is inconclusive.
   A pure ML-KEM group in a ServerHello is never called classical. */
export function decide(browser: HelloOutcome, hybridOnly: HelloOutcome, handshakes: HandshakeResult[]): { verdict: Verdict; notes: string[] } {
  const notes: string[] = [];
  const testable = handshakes.filter((h) => !CLASSICAL_GROUPS.includes(h.group) && !h.not_testable);
  const hybridDone = testable.filter((h) => h.completed);
  const classical = handshakes.filter((h) => CLASSICAL_GROUPS.includes(h.group) && !h.not_testable);
  const classicalDone = classical.some((h) => h.completed);
  const rawHybrid = browser.outcome === 'server_hello' && hybridNamed(browser);
  const list = (hs: HandshakeResult[]) => hs.map((h) => h.group).join(', ');

  const x25519 = classical.find((h) => h.group === 'X25519'), p256 = classical.find((h) => h.group === 'P-256');
  if (x25519 && !x25519.completed && p256?.completed) notes.push('X25519 refused and P-256 accepted: what a FIPS endpoint does, since it offers NIST curves only.');
  if (speaks13(browser) && classical.length > 0 && !classicalDone) notes.push(`Disagreement: the raw hello negotiated TLS 1.3, but Node handshakes restricted to ${list(classical)} failed (${classical.map((h) => h.error ?? 'no detail').join('; ')}).`);

  if (browser.outcome === 'server_hello' && browser.group && isPureMlkem(browser.group.code)) {
    notes.push(`The server selected ${browser.group.name}, a pure ML-KEM group the browser-like offer did not include; that is post-quantum but not one of the hybrid groups, and not what a conformant server should do.`);
    return { verdict: 'inconclusive', notes };
  }

  if (testable.length > 0) {
    if (hybridDone.length > 0) {
      if (hybridOnly.outcome === 'alert') notes.push(`Disagreement: the hybrid-only raw hello drew an alert (${hybridOnly.alert?.name}), but Node completed ${list(hybridDone)} with a real key; the server may validate key shares before choosing a group.`);
      if (rawHybrid) return { verdict: 'hybrid_selected', notes };
      if (!speaks13(browser) || hybridNamed(browser)) notes.push(`Node completed ${list(hybridDone)} with a real key, but the raw hello ended in ${browser.outcome}${browser.tls_version ? ` (TLS ${browser.tls_version})` : ''}${browser.error ? ` (${browser.error})` : ''}, so what the server prefers when offered a browser-like list was not observed.`);
      return { verdict: 'hybrid_supported_not_preferred', notes };
    }
    if (rawHybrid) {
      notes.push(`Disagreement: the raw hello got ${browser.group?.name} selected, but Node handshakes restricted to ${list(testable)} failed (${testable.map((h) => h.error ?? 'no detail').join('; ')}).`);
      return { verdict: 'inconclusive', notes };
    }
    if (hybridNamed(hybridOnly)) {
      notes.push(`Disagreement: the hybrid-only raw hello got ${hybridOnly.group?.name} selected, but no Node hybrid handshake completed.`);
      return { verdict: 'inconclusive', notes };
    }
    if (speaks13(browser)) return { verdict: 'classical_only', notes };
    if (browser.outcome === 'server_hello' && browser.tls_version === '1.2') return { verdict: 'tls_1_2_only', notes };
    notes.push(`Inconclusive: no hybrid handshake completed and the browser-like offer ended in ${browser.outcome}${browser.error ? ` (${browser.error})` : ''}.`);
    return { verdict: 'inconclusive', notes };
  }

  notes.push('No hybrid handshake could be run on this Node (OpenSSL 3.5 or later is needed), so the verdict rests on the hand-built hellos alone; their ML-KEM share is a placeholder.');
  if (rawHybrid) return { verdict: 'hybrid_selected', notes };
  if (hybridOnly.outcome === 'alert') {
    notes.push('Inconclusive: the hybrid-only offer drew an alert, which may mean the server rejected the placeholder share rather than the groups.');
    return { verdict: 'inconclusive', notes };
  }
  if (speaks13(browser) && hybridNamed(hybridOnly)) return { verdict: 'hybrid_supported_not_preferred', notes };
  if (speaks13(browser) && (hybridOnly.outcome === 'server_hello' || hybridOnly.outcome === 'hello_retry_request')) return { verdict: 'classical_only', notes };
  if (browser.outcome === 'server_hello' && browser.tls_version === '1.2') return { verdict: 'tls_1_2_only', notes };
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
