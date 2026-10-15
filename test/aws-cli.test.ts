/* The real CLI with synthetic credentials and a loopback AWS endpoint. Never
   contacts an account. Also runs against an installed tarball when EDGEPQ_BIN
   points to its bin/edgepq.js. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const bin = process.env.EDGEPQ_BIN ?? fileURLToPath(new URL('../bin/edgepq.js', import.meta.url));

async function runAws(endpoint: string, out: string, advisory = false, timeoutMs?: number) {
  return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
    const child = spawn(process.env.EDGEPQ_NODE ?? process.execPath, [bin, 'aws', '--regions', 'eu-west-2', '--cloudtrail-sample', '0', '--out', out, '--fail-on', 'high', '--quiet', ...(advisory ? ['--coverage', 'advisory'] : []), ...(timeoutMs ? ['--timeout', String(timeoutMs)] : [])], {
      cwd: tmpdir(), env: { ...process.env, AWS_ACCESS_KEY_ID: 'synthetic', AWS_SECRET_ACCESS_KEY: 'synthetic', AWS_REGION: 'eu-west-2', AWS_ENDPOINT_URL: endpoint, AWS_MAX_ATTEMPTS: '1', AWS_EC2_METADATA_DISABLED: 'true' },
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

test('AWS CLI: all denied fails both policies; partial requires advisory; enumerated empty succeeds', async () => {
  let mode: 'denied' | 'partial' | 'empty' | 'slow' = 'denied';
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (d) => { body += d; });
    req.on('end', () => {
      if (body.includes('Action=GetCallerIdentity')) {
        res.setHeader('content-type', 'text/xml');
        res.end('<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:iam::111111111111:user/synthetic</Arn><UserId>synthetic</UserId><Account>111111111111</Account></GetCallerIdentityResult></GetCallerIdentityResponse>');
        return;
      }
      if (mode === 'slow') return;
      const target = String(req.headers['x-amz-target'] ?? '');
      if (mode === 'empty' || mode === 'partial' && target.includes('ListKeys')) {
        if (body.includes('Action=DescribeListeners') || body.includes('Action=DescribeLoadBalancers')) {
          const action = new URLSearchParams(body).get('Action');
          res.setHeader('content-type', 'text/xml');
          res.end(`<${action}Response xmlns="http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/"><${action}Result></${action}Result></${action}Response>`);
        } else if (req.url?.includes('/distribution')) {
          res.setHeader('content-type', 'text/xml');
          res.end('<DistributionList xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Marker></Marker><MaxItems>100</MaxItems><IsTruncated>false</IsTruncated><Quantity>0</Quantity></DistributionList>');
        } else { res.setHeader('content-type', 'application/json'); res.end('{}'); }
      } else {
        res.statusCode = 403;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ __type: 'AccessDeniedException', message: 'synthetic denial' }));
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const endpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const dir = await mkdtemp(join(tmpdir(), 'edgepq-aws-cli-'));
    for (const advisory of [false, true]) {
      const out = join(dir, advisory ? 'denied-advisory' : 'denied');
      const r = await runAws(endpoint, out, advisory);
      assert.equal(r.code, 2, r.stdout + r.stderr);
      assert.match(r.stdout, /collection: failed/);
      const report = JSON.parse(await readFile(join(out, 'edgepq-findings.json'), 'utf8'));
      assert.equal(report.input.status, 'failed');
      assert.ok(report.input.not_checked.length > 0);
      assert.equal(report.summary.resources_scanned, 0);
    }
    mode = 'partial';
    const strict = await runAws(endpoint, join(dir, 'partial'));
    assert.equal(strict.code, 2, strict.stdout + strict.stderr);
    assert.match(strict.stdout, /collection: partial/);
    const advisory = await runAws(endpoint, join(dir, 'partial-advisory'), true);
    assert.equal(advisory.code, 0, advisory.stdout + advisory.stderr);
    assert.match(advisory.stderr, /advisory continuation/);
    mode = 'slow';
    const started = Date.now();
    const timed = await runAws(endpoint, join(dir, 'timed'), false, 250);
    assert.equal(timed.code, 2, timed.stdout + timed.stderr);
    assert.match(timed.stdout, /collection: failed/);
    assert.ok(Date.now() - started < 2500);
    mode = 'empty';
    const empty = await runAws(endpoint, join(dir, 'empty'));
    assert.equal(empty.code, 0, empty.stdout + empty.stderr);
    assert.match(empty.stdout, /collection: complete/);
    assert.match(empty.stdout, /0 resource\(s\)/);
  } finally { await new Promise<void>((r) => server.close(() => r())); }
});
