import test from 'node:test';
import assert from 'node:assert/strict';
import { buildReport, hostile } from '../../test/render-fixtures.ts';
import { renderHtml } from './html.ts';

test('HTML is self-contained: no scripts, no external requests, links only to sources', async () => {
  const report = await buildReport();
  const html = renderHtml(report);
  assert.ok(!/<script/i.test(html));
  assert.ok(!/<link|<img|<iframe|<object|@import|url\(/i.test(html));
  assert.ok(!/\bsrc\s*=/i.test(html));
  const sourceUrls = new Set(report.rules.flatMap((r) => r.sources.map((s) => s.url)));
  const hrefs = [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1] as string);
  assert.ok(hrefs.length > 0);
  for (const h of hrefs) assert.ok(sourceUrls.has(h.replace(/&amp;/g, '&')), `href not a source URL: ${h}`);
  assert.match(html, /prefers-color-scheme:dark/);
  assert.match(html, /name="viewport"/);
  for (const token of ['#0B2545', '#1A63B0', '#F5C242', '#5B6B85', '#DDE5EF', '#F2F6FB', '#F7F9FC']) assert.ok(html.includes(token), token);
  for (const h of ['Failed', 'Could not check', 'Already enabled']) assert.ok(html.includes(h));
});

test('values that come from user input are escaped', async () => {
  const html = renderHtml(await buildReport([hostile('aws_lb_listener.<x>"&\'')]));
  assert.ok(html.includes('aws_lb_listener.&lt;x&gt;&quot;&amp;&#39;'));
  assert.ok(!html.includes('aws_lb_listener.<x>'));
  assert.ok(!html.includes('<b>x.tf'));
});
