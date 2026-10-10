/* Node-side rule loading: every *.yaml under the rules directory, validated.
   The browser bundle gets the same files compiled in at build time, so this
   is the only place the filesystem is read for rules. */
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parse } from 'yaml';
import { validateRules } from '../engine/rules.ts';
import type { Rule } from '../engine/types.ts';

export async function loadRulesFromDir(dir: string): Promise<Rule[]> {
  const names = (await readdir(dir)).filter((n) => n.endsWith('.yaml')).sort();
  const raws: unknown[] = [];
  for (const name of names) {
    raws.push(parse(await readFile(join(dir, name), 'utf8')));
  }
  return validateRules(raws);
}
