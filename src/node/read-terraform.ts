/* Read a Terraform directory (every *.tf, not recursing into .terraform/) or
   a single JSON file, into the adapter inputs. */
import { readdir, readFile, stat } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { scanHclFiles, type HclScan } from '../adapters/hcl.ts';
import { resourcesFromTerraformJson, type PlanScan } from '../adapters/plan.ts';
import { parseHcl } from './hcl-parser.ts';

export type TerraformInput = { kind: 'hcl'; scan: HclScan; files: string[] } | { kind: 'json'; scan: PlanScan; file: string };

export async function readTerraform(target: string): Promise<TerraformInput> {
  const s = await stat(target);
  if (s.isFile()) {
    const doc: unknown = JSON.parse(await readFile(target, 'utf8'));
    return { kind: 'json', scan: resourcesFromTerraformJson(doc), file: target };
  }
  const names: string[] = [];
  const walk = async (dir: string) => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (entry.name === '.terraform' || entry.name === '.git' || entry.name === 'node_modules') continue;
        await walk(join(dir, entry.name));
      } else if (entry.name.endsWith('.tf')) {
        names.push(join(dir, entry.name));
      }
    }
  };
  await walk(target);
  names.sort();
  const files = await Promise.all(names.map(async (n) => ({ name: relative(target, n) || n, contents: await readFile(n, 'utf8') })));
  return { kind: 'hcl', scan: await scanHclFiles(files, parseHcl), files: files.map((f) => f.name) };
}
