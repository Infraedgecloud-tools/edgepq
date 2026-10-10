import test from 'node:test';
import assert from 'node:assert/strict';
import { buildReport } from '../../test/render-fixtures.ts';
import { renderMarkdown } from './markdown.ts';
import { NOT_COVERED } from './not-covered.ts';

test('Markdown has the sections in order, every finding and every rule', async () => {
  const report = await buildReport();
  const md = renderMarkdown(report);
  const order = ['## What this report does and does not say', '## Findings: Failed', '## Findings: Could not check', '## Findings: Already enabled', '## Coverage', '## Rules run'].map((h) => md.indexOf(h));
  assert.ok(order.every((i) => i >= 0), `missing section: ${order}`);
  assert.deepEqual(order, [...order].sort((a, b) => a - b));
  for (const f of report.findings) assert.ok(md.includes(`### ${f.rule.id} · ${f.resource.address}`), f.id);
  for (const r of report.rules) assert.ok(md.includes(`| ${r.id} |`), r.id);
  for (const line of NOT_COVERED) assert.ok(md.includes(line));
  assert.match(md, /\(verified \d{4}-\d{2}-\d{2}\)/);
});

test('Markdown shows defaulted values, the fix and its safety word, and never a source quote', async () => {
  const report = await buildReport();
  const md = renderMarkdown(report);
  assert.match(md, /\(defaulted\)/);
  assert.match(md, /ssl_policy = "ELBSecurityPolicy-TLS13-1-/);
  assert.match(md, /Safety: (auto|review)\./);
  for (const r of report.rules) for (const s of r.sources) if (s.quote) assert.ok(!md.includes(s.quote), r.id);
});
