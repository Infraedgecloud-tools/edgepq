import test from 'node:test';
import assert from 'node:assert/strict';
import { buildReport } from '../../test/render-fixtures.ts';
import { renderHtml } from './html.ts';
import { renderMarkdown } from './markdown.ts';

/* The project rule: the tool reports what is and is not enabled. It never calls anything safe or compliant. */
const BANNED = /quantum[- ]safe|quantum[- ]resistant|compliant|compliance/i;

test('rendered Markdown and HTML never say safe, resistant or compliant', async () => {
  const report = await buildReport([], true);
  for (const [name, text] of [['markdown', renderMarkdown(report)], ['html', renderHtml(report)]] as const) {
    const m = BANNED.exec(text);
    assert.ok(!m, `${name} contains "${m?.[0]}" near: ${m ? text.slice(Math.max(0, m.index - 80), m.index + 60) : ''}`);
  }
});
