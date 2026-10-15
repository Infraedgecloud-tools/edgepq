/* Read a Terraform directory or a single JSON file into the adapter inputs.

   A directory is read the way Terraform reads it: the *.tf files in it are
   the root module, and each `module` block with a local source pulls in that
   directory under the address module.<name>, with the call's inputs applied.
   A directory under the target that no module block calls is read as a root
   of its own, with its path as the address prefix ("modules/alb:"), so a
   repository of modules can be scanned and two resources with the same name
   in two directories never share an address. Nothing is read twice. */
import { readdir, readFile, stat, lstat } from 'node:fs/promises';
import { dirname, join, normalize, relative, resolve, sep } from 'node:path';
import type { AttrValue } from '../engine/types.ts';
import { scanHclFiles, type CoverageNote, type HclScan } from '../adapters/hcl.ts';
import { resourcesFromTerraformJson, type PlanScan } from '../adapters/plan.ts';
import { parseHcl } from './hcl-parser.ts';

/* Terraform also loads *.tf.json, whose shape is what hcl2json produces. */
const parseAny: typeof parseHcl = (filename, contents) => (filename.endsWith('.json') ? Promise.resolve(JSON.parse(contents) as unknown) : parseHcl(filename, contents));

export type TerraformInput = { kind: 'hcl'; scan: HclScan; files: string[] } | { kind: 'json'; scan: PlanScan; file: string };

const isLocalSource = (s: string) => s.startsWith('./') || s.startsWith('../') || s === '.' || s === '..';

export async function readTerraform(target: string): Promise<TerraformInput> {
  if ((await lstat(target)).isSymbolicLink()) throw new Error('Terraform input must not be a symlink');
  const s = await stat(target);
  let totalBytes = 0;
  const readBounded = async (path: string): Promise<string> => {
    const size = (await lstat(path)).size;
    totalBytes += size;
    if (size > 16 * 1024 * 1024 || totalBytes > 64 * 1024 * 1024) throw new Error('Terraform input exceeds 16 MiB per-file or 64 MiB total limit');
    return readFile(path, 'utf8');
  };
  if (s.isFile()) {
    const doc: unknown = JSON.parse(await readBounded(target));
    return { kind: 'json', scan: resourcesFromTerraformJson(doc), file: target };
  }

  /* Every *.tf under the target, grouped by the directory they are in. */
  const byDir = new Map<string, string[]>();
  let fileCount = 0;
  const walk = async (dir: string, depth = 0) => {
    if (depth > 64) throw new Error('Terraform directory depth exceeds 64');
    for (const entry of (await readdir(dir, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
      if (entry.isDirectory()) {
        if (entry.name === '.terraform' || entry.name === '.git' || entry.name === 'node_modules') continue;
        await walk(join(dir, entry.name), depth + 1);
      } else if (entry.name.endsWith('.tf') || entry.name.endsWith('.tf.json')) {
        if (entry.isSymbolicLink() || !entry.isFile()) throw new Error('Terraform source must be a regular file, not a symlink');
        if (++fileCount > 10000) throw new Error('Terraform source file count exceeds 10000');
        const list = byDir.get(dir) ?? [];
        list.push(join(dir, entry.name));
        byDir.set(dir, list);
      }
    }
  };
  await walk(resolve(target));

  const out: HclScan = { resources: [], notes: [], modules: [], variables: {}, locals: {} };
  const files: string[] = [];
  const covered = new Set<string>();
  const rel = (p: string) => relative(target, p).split(sep).join('/');

  /* Read one directory as a module and follow its local module calls. The
     chain of directories guards against a module that calls itself. */
  const readModule = async (dir: string, prefix: string, inputs: Record<string, AttrValue>, chain: string[]): Promise<void> => {
    covered.add(dir);
    const names = (byDir.get(dir) ?? []).slice().sort();
    const contents = await Promise.all(names.map(async (n) => ({ name: rel(n) || n, contents: await readBounded(n) })));
    files.push(...contents.map((f) => f.name));
    const scan = await scanHclFiles(contents, parseAny, { prefix, inputs });
    out.resources.push(...scan.resources);
    /* scanHclFiles notes every module call as not read; this reader decides
       which ones it can read, so it writes those notes itself. */
    out.notes.push(...scan.notes.filter((n) => n.kind !== 'module-call'));
    for (const m of scan.modules) {
      const address = `${prefix}module.${m.name}`;
      const note: CoverageNote = { kind: 'module-call', address, file: m.file, ...(m.source !== undefined ? { source: m.source } : {}) };
      if (m.source === undefined || !isLocalSource(m.source)) { out.notes.push(note); continue; }
      const moduleDir = normalize(resolve(dir, m.source));
      const inside = !relative(resolve(target), moduleDir).startsWith('..');
      if (!inside || !byDir.has(moduleDir) || chain.includes(moduleDir)) { out.notes.push(note); continue; }
      out.notes.push({ ...note, scanned: true });
      await readModule(moduleDir, `${address}.`, m.inputs, [...chain, moduleDir]);
    }
  };

  await readModule(resolve(target), '', {}, [resolve(target)]);
  for (const dir of [...byDir.keys()].sort()) {
    const abs = resolve(dir);
    if (covered.has(abs)) continue;
    await readModule(abs, `${rel(abs)}:`, {}, [abs]);
  }
  return { kind: 'hcl', scan: out, files };
}

/* Exported for the tests: the directory a module source resolves to. */
export const moduleDirOf = (callerFile: string, source: string): string => normalize(resolve(dirname(callerFile), source));
