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
  authenticated?: boolean;
  authentication_error?: string;
  protocol?: string;
  cipher?: string;
  error?: string;
  not_testable?: true;
};

/* OpenSSL's names for the groups, which are not the IANA spellings. */
/* Three hybrids and three classical controls. FIPS endpoints offer P-256 but
   not X25519, and a server configured for P-384 alone refuses both, so a
   classical failure means something only when every control the server
   could accept was tried. */
export const HANDSHAKE_GROUPS: readonly string[] = ['X25519MLKEM768', 'SecP256r1MLKEM768', 'SecP384r1MLKEM1024', 'X25519', 'P-256', 'P-384'];
/* Node's SSL error codes carry the alert name after the last slash. */
const describeCode = (code: string): string => {
  const m = /^ERR_SSL_SSL\/TLS_ALERT_(.+)$/.exec(code);
  if (m) return `alert ${(m[1] as string).toLowerCase()} (the server refused this group)`;
  if (code === 'ECONNRESET') return 'connection reset during handshake (reason unknown)';
  return code;
};

export const CLASSICAL_GROUPS: readonly string[] = ['X25519', 'P-256', 'P-384'];

/* The raw hello reports groups by their IANA names; the handshakes use
   OpenSSL's. The two are compared through this table. */
export const IANA_NAME: { readonly [openssl: string]: string } = { X25519: 'x25519', 'P-256': 'secp256r1', 'P-384': 'secp384r1', X25519MLKEM768: 'X25519MLKEM768', SecP256r1MLKEM768: 'SecP256r1MLKEM768', SecP384r1MLKEM1024: 'SecP384r1MLKEM1024' };

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
      clearTimeout(deadline);
      socket.destroy();
      resolve(r);
    };
    const deadline = setTimeout(() => finish({ group, completed: false, error: `no handshake within ${timeoutMs} ms` }), timeoutMs);
    socket.once('secureConnect', () => {
      const cipher = socket.getCipher();
      const identityError = socket.authorized ? tls.checkServerIdentity(servername, socket.getPeerCertificate()) : undefined;
      const authenticated = socket.authorized && !identityError;
      finish({ group, completed: true, authenticated, ...(!authenticated ? { authentication_error: (identityError as NodeJS.ErrnoException | undefined)?.code ?? String(socket.authorizationError ?? 'certificate not authenticated') } : {}), protocol: socket.getProtocol() ?? 'unknown', cipher: cipher.name });
    });
    socket.once('timeout', () => finish({ group, completed: false, error: `no handshake within ${timeoutMs} ms` }));
    /* OpenSSL's message is several lines of internal detail; the code says what happened. */
    socket.once('error', (e: NodeJS.ErrnoException) => finish({ group, completed: false, error: e.code ? describeCode(e.code) : (e.message.split('\n')[0] as string) }));
    socket.once('close', () => finish({ group, completed: false, error: 'connection closed during handshake' }));
  });
}
