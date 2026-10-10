/* CycloneDX 1.6 cryptographic bill of materials, built from the resources that
   were scanned (not from findings), so a resource with no finding is still
   inventoried. Enum strings come from the CycloneDX 1.6 schema's
   cryptoProperties definition; test/schemas holds the schema the tests use. */
import { lookup } from '../engine/predicate.ts';
import type { Resource } from '../engine/types.ts';
import type { ScanReport } from './types.ts';

type Json = { [k: string]: unknown };
type Prop = { name: string; value: string };
type Policy = { protocols?: string[]; ciphers?: string[]; post_quantum?: boolean };
type PolicyData = { hybrid_groups?: string[]; policies?: { [name: string]: Policy }; defaults?: { rest_api?: { [t: string]: string }; domain_name?: { [t: string]: string } } };

/* Read an attribute as a string, applying a default when it is absent. `unresolved` marks an expression. */
function str(r: Resource, path: string, dflt?: string): { v: string | undefined; unresolved: boolean } {
  const { value, unknown } = lookup(r, path);
  if (unknown) return { v: undefined, unresolved: true };
  const first = Array.isArray(value) ? value[0] : value;
  return { v: typeof first === 'string' ? first : dflt, unresolved: false };
}
const origin = (r: Resource) => (r.origin.kind === 'hcl' ? `hcl:${r.origin.file}` : r.origin.kind === 'plan' ? 'plan' : `aws:${r.origin.account}:${r.origin.region}`);
const base = (r: Resource, ref: string, name: string, extra: Prop[] = []): Json => ({
  type: 'cryptographic-asset', 'bom-ref': ref, name,
  properties: [{ name: 'edgepq:address', value: r.address }, { name: 'edgepq:resource_type', value: r.type }, { name: 'edgepq:origin', value: origin(r) }, ...extra],
});

/* ----------------------------------------------------------------- TLS */

function tls(r: Resource, policyName: string | undefined, unresolved: boolean, data: PolicyData | undefined, groups: string | string[] | undefined): Json {
  const ref = `edgepq:${r.address}`;
  const policy = policyName ? data?.policies?.[policyName] : undefined;
  if (!policyName || !policy) {
    const extra: Prop[] = unresolved ? [{ name: 'edgepq:unresolved', value: 'ssl_policy' }] : policyName ? [{ name: 'edgepq:policy_data', value: 'not found' }] : [];
    return { ...base(r, ref, policyName ?? 'unknown', extra), cryptoProperties: { assetType: 'protocol', protocolProperties: { type: 'tls' } } };
  }
  const versions = policy.protocols ?? [];
  const highest = versions.map((p) => p.replace('TLS', '')).sort().at(-1);
  const pq = policy.post_quantum === true && groups !== undefined;
  const kx = pq ? (Array.isArray(groups) ? groups.join(', ') : (groups as string)) : 'classical only';
  return {
    ...base(r, ref, policyName, [{ name: 'edgepq:tls_versions', value: versions.join(', ') }, { name: 'edgepq:key_exchange_groups', value: kx }]),
    cryptoProperties: { assetType: 'protocol', protocolProperties: { type: 'tls', ...(highest ? { version: highest } : {}), cipherSuites: (policy.ciphers ?? []).map((name) => ({ name })) } },
  };
}

/* ------------------------------------------------------- algorithms */

type Alg = { name: string; param: string; cl?: number; nq: number; curve?: string };
const RSA = (bits: number, cl: number): Alg => ({ name: 'RSA', param: String(bits), cl, nq: 0 });
const EC = (curve: string, cl: number, name = 'ECDSA'): Alg => ({ name, param: curve, curve, cl, nq: 0 });
const ALGS: { [spec: string]: Alg } = {
  SYMMETRIC_DEFAULT: { name: 'AES-256-GCM', param: '256', cl: 256, nq: 5 },
  RSA_1024: RSA(1024, 80), RSA_2048: RSA(2048, 112), RSA_3072: RSA(3072, 128), RSA_4096: RSA(4096, 152),
  ECC_NIST_P256: EC('P-256', 128), ECC_NIST_P384: EC('P-384', 192), ECC_NIST_P521: EC('P-521', 256),
  ECC_SECG_P256K1: EC('secp256k1', 128),
  ECC_NIST_EDWARDS25519: { name: 'Ed25519', param: 'Ed25519', curve: 'Ed25519', cl: 128, nq: 0 },
  HMAC_224: { name: 'HMAC', param: 'SHA-224', nq: 1 }, HMAC_256: { name: 'HMAC', param: 'SHA-256', nq: 1 },
  HMAC_384: { name: 'HMAC', param: 'SHA-384', nq: 3 }, HMAC_512: { name: 'HMAC', param: 'SHA-512', nq: 5 },
  ML_DSA_44: { name: 'ML-DSA', param: 'ML-DSA-44', cl: 128, nq: 2 }, ML_DSA_65: { name: 'ML-DSA', param: 'ML-DSA-65', cl: 192, nq: 3 },
  ML_DSA_87: { name: 'ML-DSA', param: 'ML-DSA-87', cl: 256, nq: 5 },
  SM2: { name: 'SM2', param: 'SM2', nq: 0 },
};
/* ACM and Private CA spell key algorithms differently from KMS. */
const ALIAS: { [k: string]: string } = { EC_prime256v1: 'ECC_NIST_P256', EC_secp384r1: 'ECC_NIST_P384', EC_secp521r1: 'ECC_NIST_P521' };
const FUNCTIONS: { [usage: string]: string[] } = {
  ENCRYPT_DECRYPT: ['encrypt', 'decrypt'], SIGN_VERIFY: ['sign', 'verify'], GENERATE_VERIFY_MAC: ['tag', 'verify'], KEY_AGREEMENT: ['keyderive'],
};

function primitive(spec: string, usage: string): string {
  if (spec === 'SYMMETRIC_DEFAULT') return 'ae';
  if (spec.startsWith('HMAC')) return 'mac';
  if (spec.startsWith('ECC_') && usage === 'KEY_AGREEMENT') return 'key-agree';
  if (usage === 'ENCRYPT_DECRYPT') return 'pke';
  return usage === 'KEY_AGREEMENT' ? 'key-agree' : 'signature';
}

function algorithm(r: Resource, ref: string, spec: string | undefined, unresolved: string | undefined, usage: string, env: 'hardware' | 'unknown', extra: Prop[] = [], functions?: string[]): Json {
  const alg = spec ? ALGS[ALIAS[spec] ?? spec] : undefined;
  const key = ALIAS[spec ?? ''] ?? spec ?? '';
  const props = [...extra, ...(unresolved ? [{ name: 'edgepq:unresolved', value: unresolved }] : []), ...(spec && !alg ? [{ name: 'edgepq:key_spec', value: spec }] : [])];
  if (!alg) return { ...base(r, ref, 'unknown', props), cryptoProperties: { assetType: 'algorithm', algorithmProperties: { primitive: 'unknown', executionEnvironment: env, cryptoFunctions: ['unknown'] } } };
  const ecdh = key.startsWith('ECC_') && !key.includes('EDWARDS') && usage === 'KEY_AGREEMENT';
  return {
    ...base(r, ref, ecdh ? 'ECDH' : alg.name, props),
    cryptoProperties: {
      assetType: 'algorithm',
      algorithmProperties: {
        primitive: primitive(key, usage), parameterSetIdentifier: alg.param, ...(alg.curve ? { curve: alg.curve } : {}),
        ...(key === 'SYMMETRIC_DEFAULT' ? { mode: 'gcm' } : {}), executionEnvironment: env,
        ...(env === 'hardware' ? { certificationLevel: ['fips140-3-l3'] } : {}),
        ...(alg.cl !== undefined ? { classicalSecurityLevel: alg.cl } : {}), nistQuantumSecurityLevel: alg.nq,
        cryptoFunctions: functions ?? FUNCTIONS[usage] ?? ['unknown'],
      },
    },
  };
}

/* ------------------------------------------------------------ resources */

const bool = (r: Resource, path: string) => lookup(r, path).value === true;

function inventory(r: Resource, report: ScanReport): Json[] {
  const elb = report.policy_data.elb as PolicyData | undefined;
  const apigw = report.policy_data.apigw as PolicyData | undefined;
  const ref = `edgepq:${r.address}`;
  switch (r.type) {
    case 'aws_lb_listener': case 'aws_alb_listener': {
      const proto = str(r, 'protocol').v;
      if (proto !== 'HTTPS' && proto !== 'TLS') return [];
      const p = str(r, 'ssl_policy', 'ELBSecurityPolicy-2016-08');
      return [tls(r, p.v, p.unresolved, elb, elb?.hybrid_groups)];
    }
    case 'aws_api_gateway_domain_name': {
      const p = str(r, 'security_policy', 'TLS_1_2');
      return [tls(r, p.v, p.unresolved, apigw, 'hybrid post-quantum (AWS does not name the groups)')];
    }
    case 'aws_api_gateway_rest_api': {
      if (bool(r, 'disable_execute_api_endpoint')) return [];
      const type = str(r, 'endpoint_configuration.types', 'EDGE').v ?? 'EDGE';
      const p = str(r, 'security_policy', apigw?.defaults?.rest_api?.[type] ?? (type === 'PRIVATE' ? 'TLS_1_2' : 'TLS_1_0'));
      return [tls(r, p.v, p.unresolved, apigw, 'hybrid post-quantum (AWS does not name the groups)')];
    }
    case 'aws_apigatewayv2_domain_name': {
      const p = str(r, 'domain_name_configuration.security_policy', 'TLS_1_2');
      return [tls(r, p.v, p.unresolved, apigw, 'hybrid post-quantum (AWS does not name the groups)')];
    }
    case 'aws_cloudfront_distribution': {
      const min = str(r, 'viewer_certificate.minimum_protocol_version', 'TLSv1');
      return [{
        ...base(r, ref, min.v ?? 'unknown', [
          { name: 'edgepq:minimum_protocol_version', value: min.v ?? 'unknown' },
          { name: 'edgepq:key_exchange_groups', value: 'X25519MLKEM768, SecP256r1MLKEM768 (TLS 1.3 viewers only)' },
          ...(min.unresolved ? [{ name: 'edgepq:unresolved', value: 'minimum_protocol_version' }] : []),
        ]),
        /* No cipher list: the CloudFront policy table is not shipped as data. */
        cryptoProperties: { assetType: 'protocol', protocolProperties: { type: 'tls', version: '1.3' } },
      }];
    }
    case 'aws_kms_key': {
      const spec = str(r, 'customer_master_key_spec', 'SYMMETRIC_DEFAULT');
      const usage = str(r, 'key_usage', 'ENCRYPT_DECRYPT');
      /* KMS keys live in FIPS 140-3 Security Level 3 validated HSMs:
         https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html */
      return [algorithm(r, ref, spec.v, spec.unresolved ? 'customer_master_key_spec' : usage.unresolved ? 'key_usage' : undefined, usage.v ?? 'ENCRYPT_DECRYPT', 'hardware')];
    }
    case 'aws_acm_certificate': {
      const imported = str(r, 'certificate_body').v !== undefined || lookup(r, 'certificate_body').unknown;
      const alg = str(r, 'key_algorithm', imported ? undefined : 'RSA_2048');
      const domain = str(r, 'domain_name').v;
      const keyRef = `${ref}:key`;
      const cert = { ...base(r, ref, domain ?? r.address, imported ? [{ name: 'edgepq:imported', value: 'true' }] : []),
        cryptoProperties: { assetType: 'certificate', certificateProperties: { ...(domain ? { subjectName: domain } : {}), subjectPublicKeyRef: keyRef } } };
      return [cert, algorithm(r, keyRef, alg.v, alg.unresolved ? 'key_algorithm' : undefined, 'SIGN_VERIFY', 'unknown')];
    }
    case 'aws_acmpca_certificate_authority': {
      const alg = str(r, 'certificate_authority_configuration.key_algorithm');
      const sig = str(r, 'certificate_authority_configuration.signing_algorithm').v;
      return [algorithm(r, ref, alg.v, alg.unresolved ? 'key_algorithm' : undefined, 'SIGN_VERIFY', 'unknown', sig ? [{ name: 'edgepq:signing_algorithm', value: sig }] : [], ['sign'])];
    }
    default: return [];
  }
}

export function renderCbom(report: ScanReport): Json {
  return {
    bomFormat: 'CycloneDX', specVersion: '1.6', serialNumber: `urn:uuid:${globalThis.crypto.randomUUID()}`, version: 1,
    metadata: { timestamp: report.generated_at, tools: { components: [{ type: 'application', name: report.tool.name, version: report.tool.version }] } },
    components: report.resources.flatMap((r) => inventory(r, report)),
  };
}
export const renderCbomJson = (report: ScanReport): string => JSON.stringify(renderCbom(report), null, 2) + '\n';
