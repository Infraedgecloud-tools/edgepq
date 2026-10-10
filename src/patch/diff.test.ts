import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { unifiedDiff } from './diff.ts';

const haveDiff = spawnSync('diff', ['--version']).status === 0;
const nums = (n: number, skip: number[] = []) => Array.from({ length: n }, (_, i) => i + 1).filter((i) => !skip.includes(i)).map((i) => `line ${i}\n`).join('');

const cases: [string, string, string][] = [
  ['one line changed', nums(20), nums(20).replace('line 10\n', 'ten\n')],
  ['two distant changes', nums(40), nums(40).replace('line 3\n', 'three\n').replace('line 30\n', 'thirty\n')],
  ['two close changes merge', nums(20), nums(20).replace('line 8\n', 'eight\n').replace('line 13\n', 'thirteen\n')],
  ['insert at start and end', nums(5), 'first\n' + nums(5) + 'last\n'],
  ['delete lines', nums(12), nums(12, [5, 6])],
  ['empty to content', '', nums(3)],
  ['content to empty', nums(3), ''],
  ['single line each', 'a\n', 'b\n'],
  ['no newline at end in new', nums(4), nums(4).slice(0, -1)],
  ['no newline at end in old', nums(4).slice(0, -1), nums(4)],
  ['no newline in both, last line changed', 'a\nb', 'a\nc'],
];

for (const [label, a, b] of cases) {
  test(`unifiedDiff matches diff -u: ${label}`, { skip: !haveDiff && 'diff is not installed' }, () => {
    const dir = mkdtempSync(join(tmpdir(), 'edgepq-diff-'));
    try {
      writeFileSync(join(dir, 'old'), a);
      writeFileSync(join(dir, 'new'), b);
      const ref = spawnSync('diff', ['-u', 'old', 'new'], { cwd: dir, encoding: 'utf8' }).stdout;
      const body = (s: string) => s.split('\n').slice(2).join('\n');
      assert.equal(body(unifiedDiff(a, b, 'f', 'f')), body(ref));
      assert.equal(unifiedDiff(a, b, 'f', 'f').split('\n').slice(0, 2).join('\n'), a === b ? '' : '--- a/f\n+++ b/f');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

test('identical text produces an empty diff', () => {
  assert.equal(unifiedDiff('a\n', 'a\n', 'f', 'f'), '');
});

/* Where GNU diff and this walk choose different but equally valid scripts
   (repeated lines), what matters is that `patch` reproduces the new text. */
test('a diff over repeated lines applies cleanly', { skip: !haveDiff && 'diff is not installed' }, () => {
  const a = 'x\nx\nx\ny\nx\n', b = 'x\ny\nx\nx\nx\n';
  const dir = mkdtempSync(join(tmpdir(), 'edgepq-diff-'));
  writeFileSync(join(dir, 'f'), a);
  writeFileSync(join(dir, 'p.diff'), unifiedDiff(a, b, 'f', 'f'));
  const r = spawnSync('patch', ['-p1', '-i', 'p.diff'], { cwd: dir, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr + r.stdout);
  assert.equal(readFileSync(join(dir, 'f'), 'utf8'), b);
});
