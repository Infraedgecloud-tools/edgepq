/* CLI input-scope regressions, exercised against source or an installed bin.
   Every AWS request is restricted to a synthetic loopback endpoint. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { spawn } from 'node:child_process';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const bin = process.env.EDGEPQ_BIN ?? join(root, 'bin/edgepq.js');
async function run(args: string[], endpoint?: string) {
  return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
    const child = spawn(process.env.EDGEPQ_NODE ?? process.execPath, [bin, ...args], {
      cwd: tmpdir(), timeout: 10000,
      env: { ...process.env, AWS_ACCESS_KEY_ID: 'synthetic', AWS_SECRET_ACCESS_KEY: 'synthetic', AWS_REGION: 'eu-west-2', AWS_ENDPOINT_URL: endpoint ?? 'http://127.0.0.1:1', AWS_MAX_ATTEMPTS: '1', AWS_EC2_METADATA_DISABLED: 'true' },
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.once('close', (code) => resolve({ code, stdout, stderr }));
  });
}

test('scan and verify reject extra positionals before analysis or network work', async () => {
  const out = await mkdtemp(join(tmpdir(), 'edgepq-scope-'));
  const scan = await run(['scan', join(root, 'test/fixtures/terraform/basic'), 'ignored.json', '--out', out]);
  assert.equal(scan.code, 2, scan.stdout + scan.stderr);
  assert.match(scan.stderr, /scan needs exactly one/);
  assert.equal(scan.stdout, '');
  const verify = await run(['verify', '127.0.0.1:1', 'ignored.example', '--timeout', '50']);
  assert.equal(verify.code, 2, verify.stdout + verify.stderr);
  assert.match(verify.stderr, /verify needs exactly one/);
  assert.equal(verify.stdout, '');
});

test('rules, help and version reject undocumented extra arguments', async () => {
  for (const command of ['rules', '--help', '-h', 'help', '--version', '-v']) {
    const result = await run([command, 'ignored']);
    assert.equal(result.code, 2, result.stdout + result.stderr);
    assert.match(result.stderr, /takes no arguments/);
    assert.equal(result.stdout, '');
  }
});

test('explicit empty AWS scopes are rejected without any AWS request', async () => {
  let requests = 0;
  const server = createServer((req, res) => {
    requests++;
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      res.setHeader('content-type', 'application/json');
      if (body.includes('Action=GetCallerIdentity')) {
        res.setHeader('content-type', 'text/xml');
        res.end('<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::111111111111:user/synthetic</Arn><UserId>synthetic</UserId><Account>111111111111</Account></GetCallerIdentityResult></GetCallerIdentityResponse>');
      } else if (body.includes('Action=DescribeRegions')) {
        res.setHeader('content-type', 'text/xml');
        res.end('<DescribeRegionsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><regionInfo><item><regionName>eu-west-2</regionName><optInStatus>opt-in-not-required</optInStatus></item></regionInfo></DescribeRegionsResponse>');
      } else if (body.includes('Action=DescribeLoadBalancers')) {
        res.setHeader('content-type', 'text/xml');
        res.end('<DescribeLoadBalancersResponse xmlns="http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/"><DescribeLoadBalancersResult></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>');
      } else if (req.url?.includes('/distribution')) {
        res.setHeader('content-type', 'text/xml');
        res.end('<DistributionList xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Marker></Marker><MaxItems>100</MaxItems><IsTruncated>false</IsTruncated><Quantity>0</Quantity></DistributionList>');
      } else res.end('{}');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    for (const flag of ['--accounts', '--regions']) {
      for (const value of ['', ',', ' , , ']) {
        requests = 0;
        const out = await mkdtemp(join(tmpdir(), 'edgepq-scope-aws-'));
        const args = ['aws', '--quiet', '--cloudtrail-sample', '0', '--out', out, ...(flag === '--accounts' ? ['--regions', 'eu-west-2'] : []), flag, value];
        const result = await run(args, endpoint);
        assert.equal(result.code, 2, result.stdout + result.stderr);
        assert.match(result.stderr, new RegExp(`${flag} requires at least one`));
        assert.equal(result.stdout, '');
        assert.equal(requests, 0, `${flag} must fail before STS or discovery`);
      }
    }
  } finally { await new Promise<void>((r) => server.close(() => r())); }
});
