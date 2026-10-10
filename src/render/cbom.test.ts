import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Ajv } from 'ajv';
import addFormats from 'ajv-formats';
import { buildReport, root } from '../../test/render-fixtures.ts';
import { renderCbom, renderCbomJson } from './cbom.ts';

const load = async (n: string) => JSON.parse(await readFile(`${root}test/schemas/${n}`, 'utf8'));
const ajv = new Ajv({ strict: false, allErrors: true });
addFormats.default(ajv);
ajv.addSchema(await load('spdx.schema.json'));
ajv.addSchema(await load('jsf-0.82.schema.json'));
const validate = ajv.compile(await load('bom-1.6.schema.json'));

type C = { 'bom-ref': string; name: string; properties: { name: string; value: string }[]; cryptoProperties: any };
const prop = (c: C, n: string) => c.properties.find((p) => p.name === n)?.value;

const report = await buildReport([], true);
const bom = renderCbom(report) as { components: C[]; serialNumber: string };
const by = (addr: string) => bom.components.filter((c) => prop(c, 'edgepq:address') === addr);
const one = (addr: string) => { const l = by(addr); assert.equal(l.length, 1, addr); return l[0] as C; };

test('the CBOM validates against the CycloneDX 1.6 schema', () => {
  assert.ok(validate(JSON.parse(renderCbomJson(report))), JSON.stringify(validate.errors?.slice(0, 5)));
  assert.match(bom.serialNumber, /^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
});

test('one protocol component per TLS listener and one algorithm per KMS key', () => {
  const tlsListeners = report.resources.filter((r) => /^aws_a?lb_listener$/.test(r.type) && ['HTTPS', 'TLS'].includes(String(r.attrs.protocol)));
  const protocols = bom.components.filter((c) => /^aws_a?lb_listener$/.test(prop(c, 'edgepq:resource_type') ?? ''));
  assert.equal(protocols.length, tlsListeners.length);
  assert.ok(protocols.every((c) => c.cryptoProperties.assetType === 'protocol'));
  const keys = report.resources.filter((r) => r.type === 'aws_kms_key');
  const algs = bom.components.filter((c) => prop(c, 'edgepq:resource_type') === 'aws_kms_key');
  assert.equal(algs.length, keys.length);
  assert.ok(keys.length >= 9 && algs.every((c) => c.cryptoProperties.assetType === 'algorithm'));
});

test('ELB listeners: policy versions, ciphers, key exchange groups, default and unresolved policy', () => {
  const pq = one('aws_lb_listener.alb_https');
  assert.equal(pq.name, 'ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09');
  assert.equal(pq.cryptoProperties.protocolProperties.version, '1.3');
  assert.ok(pq.cryptoProperties.protocolProperties.cipherSuites.length > 0);
  assert.match(prop(pq, 'edgepq:key_exchange_groups')!, /X25519MLKEM768/);
  const dflt = one('aws_alb_listener.alb_default_policy');
  assert.equal(dflt.name, 'ELBSecurityPolicy-2016-08');
  assert.equal(prop(dflt, 'edgepq:key_exchange_groups'), 'classical only');
  assert.equal(dflt.cryptoProperties.protocolProperties.version, '1.2');
  const unk = one('aws_lb_listener.nlb_tls_unresolved');
  assert.equal(unk.name, 'unknown');
  assert.equal(prop(unk, 'edgepq:unresolved'), 'ssl_policy');
  assert.equal(by('aws_lb_listener.plain_http').length, 0);
  assert.equal(by('aws_s3_bucket.ignored').length, 0);
});

test('API Gateway defaults and the execute-api opt-out', () => {
  assert.equal(one('aws_api_gateway_domain_name.domain_pq').name, 'SecurityPolicy_TLS13_1_2_PQ_2025_09');
  assert.equal(one('aws_api_gateway_domain_name.domain_default').name, 'TLS_1_2');
  assert.equal(one('aws_api_gateway_rest_api.edge_default').name, 'TLS_1_0');
  assert.equal(one('aws_api_gateway_rest_api.private').name, 'TLS_1_2');
  assert.equal(by('aws_api_gateway_rest_api.no_execute_api').length, 0);
  assert.equal(one('aws_apigatewayv2_domain_name.v2').name, 'TLS_1_2');
});

test('CloudFront reports TLS 1.3 key exchange, the default minimum version and no ciphers', () => {
  const cf = one('aws_cloudfront_distribution.cdn');
  assert.equal(prop(cf, 'edgepq:minimum_protocol_version'), 'TLSv1');
  assert.match(prop(cf, 'edgepq:key_exchange_groups')!, /SecP256r1MLKEM768/);
  assert.equal(cf.cryptoProperties.protocolProperties.cipherSuites, undefined);
});

test('KMS key specs map to the documented algorithm properties', () => {
  const a = (addr: string) => one(addr).cryptoProperties.algorithmProperties;
  assert.deepEqual([one('aws_kms_key.symmetric').name, a('aws_kms_key.symmetric').primitive, a('aws_kms_key.symmetric').mode, a('aws_kms_key.symmetric').nistQuantumSecurityLevel], ['AES-256-GCM', 'ae', 'gcm', 5]);
  assert.equal(a('aws_kms_key.rsa_encrypt').primitive, 'pke');
  assert.equal(a('aws_kms_key.rsa_encrypt').classicalSecurityLevel, 128);
  assert.equal(a('aws_kms_key.rsa_sign').primitive, 'signature');
  assert.equal(a('aws_kms_key.ecdsa').curve, 'P-384');
  assert.equal(one('aws_kms_key.ecdh').name, 'ECDH');
  assert.equal(a('aws_kms_key.ecdh').primitive, 'key-agree');
  assert.deepEqual(a('aws_kms_key.ecdh').cryptoFunctions, ['keyderive']);
  assert.equal(one('aws_kms_key.ed25519').name, 'Ed25519');
  assert.equal(a('aws_kms_key.hmac').nistQuantumSecurityLevel, 3);
  assert.deepEqual(a('aws_kms_key.hmac').cryptoFunctions, ['tag', 'verify']);
  const ml = a('aws_kms_key.mldsa');
  assert.deepEqual([one('aws_kms_key.mldsa').name, ml.parameterSetIdentifier, ml.nistQuantumSecurityLevel, ml.classicalSecurityLevel], ['ML-DSA', 'ML-DSA-65', 3, 192]);
  assert.deepEqual([ml.executionEnvironment, ml.certificationLevel], ['hardware', ['fips140-3-l3']]);
  assert.equal(one('aws_kms_key.sm2').name, 'SM2');
  const bad = one('aws_kms_key.unresolved');
  assert.equal(bad.name, 'unknown');
  assert.equal(prop(bad, 'edgepq:unresolved'), 'customer_master_key_spec');
});

test('ACM certificates link to their key algorithm; imported ones are marked; Private CA keeps its signing algorithm', () => {
  const certs = by('aws_acm_certificate.default_key');
  assert.equal(certs.length, 2);
  const cert = certs.find((c) => c.cryptoProperties.assetType === 'certificate')!;
  const key = certs.find((c) => c.cryptoProperties.assetType === 'algorithm')!;
  assert.equal(cert.cryptoProperties.certificateProperties.subjectName, 'www.example.com');
  assert.equal(cert.cryptoProperties.certificateProperties.subjectPublicKeyRef, key['bom-ref']);
  assert.equal(key.cryptoProperties.algorithmProperties.parameterSetIdentifier, '2048');
  const ec = by('aws_acm_certificate.ec').find((c) => c.cryptoProperties.assetType === 'algorithm')!;
  assert.equal(ec.cryptoProperties.algorithmProperties.curve, 'P-256');
  const imported = by('aws_acm_certificate.imported');
  assert.ok(imported.some((c) => prop(c, 'edgepq:imported') === 'true'));
  assert.ok(imported.some((c) => c.cryptoProperties.assetType === 'algorithm' && c.name === 'unknown'));
  const ca = one('aws_acmpca_certificate_authority.classical');
  assert.equal(prop(ca, 'edgepq:signing_algorithm'), 'SHA512WITHRSA');
  assert.deepEqual([ca.cryptoProperties.algorithmProperties.executionEnvironment, ca.cryptoProperties.algorithmProperties.cryptoFunctions], ['unknown', ['sign']]);
  assert.equal(one('aws_acmpca_certificate_authority.mldsa').name, 'ML-DSA');
});

test('bom-refs are unique within the inventory file and origins are recorded', () => {
  const inv = bom.components.filter((c) => /inventory\/main\.tf$/.test(prop(c, 'edgepq:origin') ?? ''));
  const refs = inv.map((c) => c['bom-ref']);
  assert.equal(new Set(refs).size, refs.length);
  assert.match(prop(one('aws_kms_key.symmetric'), 'edgepq:origin')!, /^hcl:.*inventory\/main\.tf$/);
});
