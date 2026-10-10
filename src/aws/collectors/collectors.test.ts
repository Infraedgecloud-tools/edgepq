import test from 'node:test';
import assert from 'node:assert/strict';
import { mockClient } from 'aws-sdk-client-mock';
import { ElasticLoadBalancingV2Client, DescribeListenersCommand, DescribeLoadBalancersCommand } from '@aws-sdk/client-elastic-load-balancing-v2';
import { CloudFrontClient, ListDistributionsCommand } from '@aws-sdk/client-cloudfront';
import { APIGatewayClient, GetDomainNamesCommand, GetRestApisCommand } from '@aws-sdk/client-api-gateway';
import { ApiGatewayV2Client, GetDomainNamesCommand as GetV2DomainNamesCommand } from '@aws-sdk/client-apigatewayv2';
import { KMSClient, DescribeKeyCommand, ListKeysCommand } from '@aws-sdk/client-kms';
import { ACMClient, ListCertificatesCommand } from '@aws-sdk/client-acm';
import { ACMPCAClient, ListCertificateAuthoritiesCommand } from '@aws-sdk/client-acm-pca';
import { LambdaClient, ListFunctionsCommand } from '@aws-sdk/client-lambda';
import { CloudTrailClient, LookupEventsCommand } from '@aws-sdk/client-cloudtrail';
import { elbv2 } from './elbv2.ts';
import { cloudfront } from './cloudfront.ts';
import { apigateway, apigatewayv2 } from './apigateway.ts';
import { kms } from './kms.ts';
import { acm, acmpca } from './certificates.ts';
import { lambda } from './lambda.ts';
import { cloudtrail, summarise } from './cloudtrail.ts';
import { loadRulesFromDir } from '../../node/load-rules.ts';
import { evaluateAll } from '../../engine/evaluate.ts';
import type { CollectorContext } from '../types.ts';

const ctx: CollectorContext = { scope: { account: '123456789012', region: 'eu-west-2' }, credentials: undefined, cloudTrailSample: 200 };
const rulesDir = new URL('../../../rules/', import.meta.url).pathname;

test('elbv2: listeners across paginated load balancers and listeners', async () => {
  const m = mockClient(ElasticLoadBalancingV2Client);
  m.on(DescribeLoadBalancersCommand, {}).resolves({ LoadBalancers: [{ LoadBalancerArn: 'arn:lb/1', Type: 'application' }], NextMarker: 'p2' })
    .on(DescribeLoadBalancersCommand, { Marker: 'p2' }).resolves({ LoadBalancers: [{ LoadBalancerArn: 'arn:lb/2', Type: 'network' }] })
    .on(DescribeListenersCommand, { LoadBalancerArn: 'arn:lb/1' }).resolves({ Listeners: [
      { ListenerArn: 'arn:l/1a', Port: 443, Protocol: 'HTTPS', SslPolicy: 'ELBSecurityPolicy-2016-08' },
      { ListenerArn: 'arn:l/1b', Port: 80, Protocol: 'HTTP' },
    ] })
    .on(DescribeListenersCommand, { LoadBalancerArn: 'arn:lb/2' }).resolves({ Listeners: [{ ListenerArn: 'arn:l/2a', Port: 443, Protocol: 'TLS', SslPolicy: 'ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09' }] });
  const { resources } = await elbv2.run(ctx);
  assert.deepEqual(resources.map((r) => [r.address, r.attrs.protocol, r.attrs.ssl_policy]), [
    ['arn:l/1a', 'HTTPS', 'ELBSecurityPolicy-2016-08'], ['arn:l/1b', 'HTTP', undefined], ['arn:l/2a', 'TLS', 'ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09'],
  ]);
  assert.deepEqual(resources[0]?.origin, { kind: 'aws', account: '123456789012', region: 'eu-west-2', arn: 'arn:l/1a' });
  const findings = evaluateAll(await loadRulesFromDir(rulesDir), resources).filter((f) => f.rule.id === 'ELB-KX-001');
  assert.deepEqual(findings.map((f) => [f.resource.address, f.status]), [['arn:l/1a', 'fail'], ['arn:l/2a', 'pass']]);
  m.restore();
});

test('cloudfront: shaped like the Terraform resource, rules apply unchanged', async () => {
  const m = mockClient(CloudFrontClient);
  m.on(ListDistributionsCommand).resolves({ DistributionList: { Items: [
    { ARN: 'arn:cf/1', Id: 'E1', Enabled: true, Aliases: { Items: ['www.example.com'] },
      DefaultCacheBehavior: { ViewerProtocolPolicy: 'redirect-to-https' },
      CacheBehaviors: { Items: [{ PathPattern: '/legacy/*', ViewerProtocolPolicy: 'allow-all' }] },
      ViewerCertificate: { CloudFrontDefaultCertificate: false, MinimumProtocolVersion: 'TLSv1.2_2021', ACMCertificateArn: 'arn:acm/1' } },
    { ARN: 'arn:cf/2', Id: 'E2', Enabled: true, DefaultCacheBehavior: { ViewerProtocolPolicy: 'https-only' }, ViewerCertificate: { CloudFrontDefaultCertificate: true } },
  ] } } as never);
  const { resources } = await cloudfront.run(ctx);
  const findings = evaluateAll(await loadRulesFromDir(rulesDir), resources);
  assert.deepEqual(findings.map((f) => [f.rule.id, f.resource.address, f.status]), [
    ['CF-KX-001', 'arn:cf/1', 'fail'], ['CF-KX-001', 'arn:cf/2', 'pass'], ['CF-KX-002', 'arn:cf/1', 'pass'],
  ]);
  m.restore();
});

test('api gateway: domains, rest apis and v2 domains with service defaults left absent', async () => {
  const m = mockClient(APIGatewayClient);
  m.on(GetDomainNamesCommand).resolves({ items: [
    { domainName: 'api.example.com', securityPolicy: 'TLS_1_2', endpointConfiguration: { types: ['REGIONAL'] } },
    { domainName: 'edge.example.com', endpointConfiguration: { types: ['EDGE'] } },
  ] });
  m.on(GetRestApisCommand).resolves({ items: [
    { id: 'abc123', name: 'orders', endpointConfiguration: { types: ['REGIONAL'] } },
    { id: 'def456', name: 'pq', securityPolicy: 'SecurityPolicy_TLS13_1_2_PQ_2025_09', endpointAccessMode: 'BASIC', endpointConfiguration: { types: ['PRIVATE'] } },
  ] });
  const v2 = mockClient(ApiGatewayV2Client);
  v2.on(GetV2DomainNamesCommand, {}).resolves({ Items: [{ DomainName: 'h1.example.com', DomainNameConfigurations: [{ SecurityPolicy: 'TLS_1_2', EndpointType: 'REGIONAL' }] }], NextToken: 'n' })
    .on(GetV2DomainNamesCommand, { NextToken: 'n' }).resolves({ Items: [{ DomainName: 'h2.example.com', DomainNameConfigurations: [{ SecurityPolicy: 'TLS_1_2', EndpointType: 'REGIONAL' }] }] });
  const a = await apigateway.run(ctx);
  const b = await apigatewayv2.run(ctx);
  assert.equal(a.resources.length, 4);
  assert.equal(b.resources.length, 2);
  const all = [...a.resources, ...b.resources];
  const name = (address: string) => { const r = all.find((x) => x.address === address)!; return r.attrs.domain_name ?? r.attrs.name; };
  const findings = evaluateAll(await loadRulesFromDir(rulesDir), all);
  assert.deepEqual(findings.map((f) => [f.rule.id, name(f.resource.address), f.status]), [
    ['APIGW-KX-001', 'api.example.com', 'fail'], ['APIGW-KX-003', 'orders', 'fail'],
    ['APIGW-KX-002', 'edge.example.com', 'fail'],
    ['APIGW-KX-006', 'h1.example.com', 'fail'], ['APIGW-KX-006', 'h2.example.com', 'fail'],
    ['APIGW-KX-004', 'pq', 'pass'],
  ]);
  m.restore(); v2.restore();
});

test('kms: customer keys only, AWS-managed and pending deletion counted in notes', async () => {
  const m = mockClient(KMSClient);
  m.on(ListKeysCommand).resolves({ Keys: [{ KeyId: 'k1' }, { KeyId: 'k2' }, { KeyId: 'k3' }, { KeyId: 'k4' }] });
  m.on(DescribeKeyCommand, { KeyId: 'k1' }).resolves({ KeyMetadata: { KeyId: 'k1', Arn: 'arn:kms/k1', KeyManager: 'CUSTOMER', KeyState: 'Enabled', KeySpec: 'RSA_2048', KeyUsage: 'ENCRYPT_DECRYPT' } });
  m.on(DescribeKeyCommand, { KeyId: 'k2' }).resolves({ KeyMetadata: { KeyId: 'k2', Arn: 'arn:kms/k2', KeyManager: 'AWS', KeyState: 'Enabled', KeySpec: 'SYMMETRIC_DEFAULT', KeyUsage: 'ENCRYPT_DECRYPT' } });
  m.on(DescribeKeyCommand, { KeyId: 'k3' }).resolves({ KeyMetadata: { KeyId: 'k3', Arn: 'arn:kms/k3', KeyManager: 'CUSTOMER', KeyState: 'PendingDeletion', KeySpec: 'RSA_2048', KeyUsage: 'SIGN_VERIFY' } });
  m.on(DescribeKeyCommand, { KeyId: 'k4' }).resolves({ KeyMetadata: { KeyId: 'k4', Arn: 'arn:kms/k4', KeyManager: 'CUSTOMER', KeyState: 'Enabled', KeySpec: 'ML_DSA_65', KeyUsage: 'SIGN_VERIFY' } });
  const { resources, notes } = await kms.run(ctx);
  assert.deepEqual(resources.map((r) => r.address), ['arn:kms/k1', 'arn:kms/k4']);
  assert.equal(notes?.length, 2);
  const findings = evaluateAll(await loadRulesFromDir(rulesDir), resources);
  assert.deepEqual(findings.map((f) => [f.rule.id, f.status]), [['KMS-KX-001', 'fail'], ['KMS-SIG-001', 'pass']]);
  m.restore();
});

test('acm and private ca', async () => {
  const a = mockClient(ACMClient);
  a.on(ListCertificatesCommand).resolves({ CertificateSummaryList: [
    { CertificateArn: 'arn:acm/1', DomainName: 'www.example.com', KeyAlgorithm: 'RSA_2048', Type: 'AMAZON_ISSUED', Status: 'ISSUED', InUse: true },
    { CertificateArn: 'arn:acm/2', DomainName: 'old.example.com', KeyAlgorithm: 'EC_prime256v1', Type: 'IMPORTED', Status: 'ISSUED', InUse: false },
  ] });
  const p = mockClient(ACMPCAClient);
  p.on(ListCertificateAuthoritiesCommand).resolves({ CertificateAuthorities: [
    { Arn: 'arn:pca/1', Type: 'ROOT', Status: 'ACTIVE', CertificateAuthorityConfiguration: { KeyAlgorithm: 'RSA_4096', SigningAlgorithm: 'SHA512WITHRSA', Subject: {} } },
    { Arn: 'arn:pca/2', Type: 'ROOT', Status: 'DELETED', CertificateAuthorityConfiguration: { KeyAlgorithm: 'RSA_4096', SigningAlgorithm: 'SHA512WITHRSA', Subject: {} } },
    { Arn: 'arn:pca/3', Type: 'SUBORDINATE', Status: 'ACTIVE', CertificateAuthorityConfiguration: { KeyAlgorithm: 'ML_DSA_65', SigningAlgorithm: 'ML_DSA_65', Subject: {} } },
  ] } as never);
  const certs = await acm.run(ctx);
  const cas = await acmpca.run(ctx);
  assert.equal(certs.resources.length, 2);
  assert.equal(certs.resources[1]?.attrs.certificate_body, '(imported)');
  assert.deepEqual(cas.resources.map((r) => r.address), ['arn:pca/1', 'arn:pca/3']);
  const findings = evaluateAll(await loadRulesFromDir(rulesDir), [...certs.resources, ...cas.resources]);
  assert.deepEqual(findings.map((f) => [f.rule.id, f.resource.address, f.status]), [['PCA-SIG-001', 'arn:pca/1', 'fail'], ['PCA-SIG-001', 'arn:pca/3', 'pass']]);
  a.restore(); p.restore();
});

test('lambda layers feed the extension rule', async () => {
  const m = mockClient(LambdaClient);
  m.on(ListFunctionsCommand).resolves({ Functions: [
    { FunctionArn: 'arn:fn/old', FunctionName: 'old', Runtime: 'nodejs22.x', Layers: [{ Arn: 'arn:aws:lambda:eu-west-2:133256977650:layer:AWS-Parameters-and-Secrets-Lambda-Extension:11' }] },
    { FunctionArn: 'arn:fn/new', FunctionName: 'new', Runtime: 'nodejs22.x', Layers: [{ Arn: 'arn:aws:lambda:eu-west-2:133256977650:layer:AWS-Parameters-and-Secrets-Lambda-Extension:123' }] },
    { FunctionArn: 'arn:fn/none', FunctionName: 'none', Runtime: 'python3.13' },
  ] });
  const { resources } = await lambda.run(ctx);
  const findings = evaluateAll(await loadRulesFromDir(rulesDir), resources);
  assert.deepEqual(findings.map((f) => [f.resource.address, f.status]), [['arn:fn/old', 'fail'], ['arn:fn/new', 'pass']]);
  m.restore();
});

const event = (kx: string | undefined, ua = 'aws-cli/2.15.30') => JSON.stringify({ userAgent: ua, ...(kx ? { tlsDetails: { tlsVersion: 'TLSv1.3', keyExchange: kx } } : {}) });

test('cloudtrail: the sample counts classical vs hybrid and ignores service-made calls', () => {
  const s = summarise([event('X25519MLKEM768'), event('x25519', 'boto3/1.34'), event('secp256r1', 'boto3/1.34'), event(undefined), 'not json']);
  assert.deepEqual(s, { events_sampled: 3, classical_count: 2, hybrid_count: 1, user_agents_classical: ['boto3/1.34 (2)'], no_tls_details: 1 });
});

test('cloudtrail: one synthetic resource per service, capped at the sample size', async () => {
  const m = mockClient(CloudTrailClient);
  m.on(LookupEventsCommand, { LookupAttributes: [{ AttributeKey: 'EventSource', AttributeValue: 'kms.amazonaws.com' }] })
    .resolvesOnce({ Events: Array.from({ length: 50 }, () => ({ CloudTrailEvent: event('X25519MLKEM768') })), NextToken: 'n' })
    .resolves({ Events: Array.from({ length: 50 }, () => ({ CloudTrailEvent: event('x25519', 'aws-sdk-java/1.12') })) });
  m.on(LookupEventsCommand, { LookupAttributes: [{ AttributeKey: 'EventSource', AttributeValue: 'secretsmanager.amazonaws.com' }] }).resolves({ Events: [] });
  const { resources } = await cloudtrail.run({ ...ctx, cloudTrailSample: 60 });
  assert.equal(resources.length, 2);
  assert.deepEqual([resources[0]?.attrs.events_sampled, resources[0]?.attrs.hybrid_count, resources[0]?.attrs.classical_count], [60, 50, 10]);
  const findings = evaluateAll(await loadRulesFromDir(rulesDir), resources);
  assert.deepEqual(findings.map((f) => [f.resource.address, f.status]), [['edgepq:123456789012:eu-west-2:kms.amazonaws.com', 'fail']]);
  assert.match(findings[0]!.message, /of 60 recent calls sampled from CloudTrail, 10 negotiated a classical/);
  m.restore();
});

test('cloudtrail: sample of zero disables the collector', async () => {
  const out = await cloudtrail.run({ ...ctx, cloudTrailSample: 0 });
  assert.deepEqual(out.resources, []);
});
