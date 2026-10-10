/* ============================================================================
   Code points the probe sends or decodes. Node-only module tree: nothing
   outside src/probe/ may import it.

   Groups: IANA TLS Supported Groups registry, read 2026-10-10
   https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
   ========================================================================= */

export const X25519MLKEM768 = 4588;
export const SECP256R1MLKEM768 = 4587;
export const SECP384R1MLKEM1024 = 4589;
export const X25519 = 29;
export const SECP256R1 = 23;
export const SECP384R1 = 24;

export const HYBRID_GROUPS: readonly number[] = [X25519MLKEM768, SECP256R1MLKEM768, SECP384R1MLKEM1024];

/* Decoded only. The pure and draft-only entries are never offered, but a
   server that picks one is named rather than shown as a number. */
const GROUP_NAMES: { [code: number]: string } = {
  [X25519MLKEM768]: 'X25519MLKEM768',
  [SECP256R1MLKEM768]: 'SecP256r1MLKEM768',
  [SECP384R1MLKEM1024]: 'SecP384r1MLKEM1024',
  [X25519]: 'x25519',
  [SECP256R1]: 'secp256r1',
  [SECP384R1]: 'secp384r1',
  512: 'MLKEM512',
  513: 'MLKEM768',
  514: 'MLKEM1024',
  4585: 'SecP256r1MLKEM512',
  4586: 'MLKEM512X25519',
  4590: 'curveSM2MLKEM768',
};

const hex = (n: number) => '0x' + n.toString(16).padStart(4, '0');

export const groupName = (code: number): string => GROUP_NAMES[code] ?? `unknown(${hex(code)})`;
export const isHybrid = (code: number): boolean => HYBRID_GROUPS.includes(code);

const CIPHER_NAMES: { [code: number]: string } = {
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
};
export const cipherName = (code: number): string => CIPHER_NAMES[code] ?? `unknown(${hex(code)})`;

const ALERT_NAMES: { [code: number]: string } = {
  0: 'close_notify', 10: 'unexpected_message', 40: 'handshake_failure', 47: 'illegal_parameter',
  50: 'decode_error', 70: 'protocol_version', 71: 'insufficient_security', 80: 'internal_error',
  112: 'unrecognized_name',
};
export const alertName = (code: number): string => ALERT_NAMES[code] ?? `unknown(${code})`;
