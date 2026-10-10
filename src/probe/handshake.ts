/* ============================================================================
   Cross-check with Node's own TLS stack (OpenSSL 3.5). One full handshake per
   group, restricted to that group and to TLS 1.3, so a completed handshake
   means the server accepted exactly that group.

   getEphemeralKeyInfo() returns {} for TLS 1.3 on this version, so success or
   failure of the handshake is the only signal used.
   ========================================================================= */

import tls from 'node:tls';

export type HandshakeResult = {
  group: string;
  completed: boolean;
  protocol?: string;
  cipher?: string;
  error?: string;
  not_testable?: true;
};

/* OpenSSL's names for the groups, which are not the IANA spellings. */
export const HANDSHAKE_GROUPS: readonly string[] = ['X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024', 'X25519'];

export function tryHandshake(host: string, port: number, servername: string, group: string, timeoutMs: number): Promise<HandshakeResult> {
  return new Promise((resolve) => {
    let socket: tls.TLSSocket;
    try {
      socket = tls.connect({
        host, port, ecdhCurve: group, minVersion: 'TLSv1.3', rejectUnauthorized: false, timeout: timeoutMs,
        ...(servername && !/^[\d.]+$|:/.test(servername) ? { servername } : {}),
      });
    } catch (e) {
      /* OpenSSL refused the group name: a limit of this Node, not of the server. */
      resolve({ group, completed: false, not_testable: true, error: (e as Error).message });
      return;
    }
    let done = false;
    const finish = (r: HandshakeResult) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(r);
    };
    socket.once('secureConnect', () => {
      const cipher = socket.getCipher();
      finish({ group, completed: true, protocol: socket.getProtocol() ?? 'unknown', cipher: cipher.name });
    });
    socket.once('timeout', () => finish({ group, completed: false, error: `no handshake within ${timeoutMs} ms` }));
    socket.once('error', (e: NodeJS.ErrnoException) => finish({ group, completed: false, error: e.code ? `${e.code}: ${e.message}` : e.message }));
    socket.once('close', () => finish({ group, completed: false, error: 'connection closed during handshake' }));
  });
}
