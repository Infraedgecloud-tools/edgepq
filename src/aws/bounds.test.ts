import test from 'node:test';
import assert from 'node:assert/strict';
import { checkedPages, AWS_LIMITS } from './bounds.ts';

test('AWS retries and request budgets are finite', () => {
  assert.equal(AWS_LIMITS.maxAttempts, 3);
  assert.equal(AWS_LIMITS.requestHandler.connectionTimeout, 2000);
  assert.equal(AWS_LIMITS.requestHandler.requestTimeout, 10000);
  assert.equal(AWS_LIMITS.requestHandler.throwOnRequestTimeout, true);
});

test('pagination fails on repeated tokens instead of reporting truncation complete', async () => {
  async function* source() { yield { NextToken: 'again' }; yield { NextToken: 'again' }; }
  await assert.rejects(async () => { for await (const _page of checkedPages(source())) {} }, /repeated/);
});

test('pagination caps unique pages and honors cancellation', async () => {
  async function* source() { for (let i = 0; i < 1001; i++) yield { NextToken: String(i) }; }
  await assert.rejects(async () => { for await (const _page of checkedPages(source())) {} }, /1000/);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(async () => { for await (const _page of checkedPages(source(), controller.signal)) {} }, /abort/i);
});
