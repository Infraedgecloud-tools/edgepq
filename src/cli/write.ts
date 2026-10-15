/* Write every output of a scan into one directory. Returns what was written
   so the console summary and the tests can say so. */
import { mkdir, readFile, writeFile, mkdtemp, rename, readdir, lstat, unlink, rmdir, rm, open }
from 'node:fs/promises';
import { resolve, dirname, basename, sep } from 'node:path';

import { join, relative } from 'node:path';
import { renderJson } from '../render/json.ts';
import { renderMarkdown } from '../render/markdown.ts';
import { renderHtml } from '../render/html.ts';
import { renderCbomJson } from '../render/cbom.ts';
import { renderSarif, type SarifLocations } from '../render/sarif.ts';
import { locateResource } from '../patch/locate.ts';
import type { Finding } from '../engine/types.ts';
import { buildPatchesWithSkips, combinePatches } from '../patch/index.ts';
import type { ScanReport } from '../render/types.ts';
import type { TerraformInput } from '../node/read-terraform.ts';

export type Written = { files: string[]; patches: number; patchesSkipped: { ruleId: string; address: string; reason: string }[]; perFixFilesOmitted?: boolean };

export const OUTPUT_NAMES = {
  json: 'edgepq-findings.json',
  markdown: 'edgepq-report.md',
  html: 'edgepq-report.html',
  cbom: 'edgepq-cbom.cdx.json',
  sarif: 'edgepq-findings.sarif',
  patchesDir: 'patches',
  autoPatch: 'edgepq-auto.patch',
  allPatch: 'edgepq-all.patch',
};

async function writeRun(report: ScanReport, outDir: string, source?: { target: string; input: TerraformInput }): Promise<Written> {
  await mkdir(outDir, { recursive: true });
  const files: string[] = [];
  const put = async (name: string, contents: string) => {
    await writeFile(join(outDir, name), contents);
    files.push(name);
  };
  const written: Written = { files, patches: 0, patchesSkipped: [] };

  /* The HCL sources serve the patches and the SARIF line numbers. */
  const sources = source && source.input.kind === 'hcl'
    ? await Promise.all(source.input.files.map(async (name) => ({ name, contents: await readFile(join(source.target, name), 'utf8') })))
    : [];

  /* Patches first, so the fixes that could not be written are in the report. */
  let patches: ReturnType<typeof buildPatchesWithSkips>['patches'] = [];
  if (source && source.input.kind === 'hcl' && report.input.kind === 'hcl') {
    const built = buildPatchesWithSkips(report.findings, sources);
    patches = built.patches;
    written.patchesSkipped = built.skipped.map((s) => ({ ruleId: s.ruleId, address: s.address, reason: s.reason }));
    if (written.patchesSkipped.length) report.input.patches_skipped = written.patchesSkipped;
  }

  await put(OUTPUT_NAMES.json, renderJson(report));
  await put(OUTPUT_NAMES.markdown, renderMarkdown(report));
  await put(OUTPUT_NAMES.html, renderHtml(report));
  await put(OUTPUT_NAMES.cbom, renderCbomJson(report));
  await put(OUTPUT_NAMES.sarif, renderSarif(report, sarifLocations(source, sources)));
  if (patches.length === 0) return written;
  await mkdir(join(outDir, OUTPUT_NAMES.patchesDir), { recursive: true });
  /* One file per fix is useful up to a point; past it the combined patches
     and the JSON carry the same information without a thousand files. */
  const PER_FIX_LIMIT = 200;
  written.patches = patches.length;
  if (patches.length <= PER_FIX_LIMIT) {
    for (const p of patches) {
      const name = `${OUTPUT_NAMES.patchesDir}/${p.ruleId}-${p.address.replace(/[^A-Za-z0-9_.-]+/g, '_')}.patch`;
      if (files.includes(name)) throw new Error(`patch filename collision: ${name}`);
      await put(name, p.diff);
    }
  } else {
    written.perFixFilesOmitted = true;
  }
  const auto = combinePatches(patches, { safety: 'auto' });
  if (auto.included.length) await put(`${OUTPUT_NAMES.patchesDir}/${OUTPUT_NAMES.autoPatch}`, auto.diff);
  const all = combinePatches(patches, { safety: 'all' });
  if (all.included.length) await put(`${OUTPUT_NAMES.patchesDir}/${OUTPUT_NAMES.allPatch}`, all.diff);
  return written;
}


const MANIFEST = '.edgepq-output.json';

/* A complete output directory belongs to one run. Stage beside it, then swap
   directories. Refuse to adopt nonempty unowned directories, symlinks, or user
   additions. No arbitrary output directory is ever recursively removed. */
export async function writeOutputs(report: ScanReport, outDir: string, source?: { target: string; input: TerraformInput }): Promise<Written> {
  const destination = resolve(outDir);
  if (source) {
    const input = resolve(source.target);
    if (input === destination || input.startsWith(destination + sep)) throw new Error('output directory would replace the input');
  }
  const parent = dirname(destination);
  await mkdir(parent, { recursive: true });
  // Reject symlink components rather than following an output into another tree.
  for (let path = parent;; path = dirname(path)) {
    if ((await lstat(path)).isSymbolicLink()) throw new Error('output path contains a symlink');
    if (dirname(path) === path) break;
  }
  const lockPath = destination + '.edgepq-lock';
  const lock = await open(lockPath, 'wx');
  let stage: string | undefined;
  let backup: string | undefined;
  try {
    let owned: string[] = [];
    let exists = false;
    try {
      const st = await lstat(destination);
      exists = true;
      if (!st.isDirectory() || st.isSymbolicLink()) throw new Error('output path must be a real directory');
      const actual = await listFiles(destination);
      if (actual.length) {
        let manifest: unknown;
        try { manifest = JSON.parse(await readFile(join(destination, MANIFEST), 'utf8')); }
        catch { throw new Error('nonempty output directory is not owned by EdgePQ; select a new empty directory'); }
        if (!manifest || typeof manifest !== 'object' || !('version' in manifest) || manifest.version !== 1 || !('files' in manifest) || !Array.isArray(manifest.files)) throw new Error('invalid EdgePQ output manifest');
        owned = manifest.files as string[];
        if (owned.some((f) => typeof f !== 'string' || !/^(edgepq-[A-Za-z0-9.-]+|patches\/[A-Za-z0-9_.-]+\.patch)$/.test(f))) throw new Error('invalid owned output path');
        if (JSON.stringify([...actual].sort()) !== JSON.stringify([...owned, MANIFEST].sort())) throw new Error('output directory contains unowned or missing files; select a new empty directory');
      }
    } catch (e) { if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e; }
    stage = await mkdtemp(join(parent, '.' + basename(destination) + '-run-'));
    const written = await writeRun(report, stage, source);
    await writeFile(join(stage, MANIFEST), JSON.stringify({ version: 1, files: written.files }) + '\n', { flag: 'wx' });
    if (exists) {
      backup = stage + '-previous';
      await rename(destination, backup);
    }
    try { await rename(stage, destination); stage = undefined; }
    catch (e) { if (backup) { await rename(backup, destination); backup = undefined; } throw e; }
    if (backup) {
      // Delete only the exact files verified above; user-selected trees are never rm -rf'd.
      for (const file of [...owned, ...(owned.length ? [MANIFEST] : [])]) await unlink(join(backup, file));
      if (owned.some((f) => f.startsWith('patches/'))) await rmdir(join(backup, 'patches'));
      await rmdir(backup);
      backup = undefined;
    }
    return written;
  } finally {
    if (stage) await rm(stage, { recursive: true, force: true }); // only our mkdtemp directory
    await lock.close();
    await unlink(lockPath);
  }
}

async function listFiles(dir: string, prefix = ''): Promise<string[]> {
  const result: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const name = prefix + entry.name;
    if (entry.isSymbolicLink()) throw new Error('output directory contains a symlink');
    if (entry.isDirectory()) {
      if (name !== 'patches') throw new Error('output directory contains an unowned directory');
      const nested = await listFiles(join(dir, entry.name), name + '/');
      if (!nested.length) throw new Error('output directory contains an unowned empty directory');
      result.push(...nested);
    } else if (entry.isFile()) result.push(name);
    else throw new Error('output directory contains a special file');
  }
  return result;
}


/* SARIF paths are relative to the working directory, which is the repository
   root when the scan runs in CI, and the region is the resource block's first
   line. A scan of a plan file has a file to name but no block to point at. */
function sarifLocations(source: { target: string; input: TerraformInput } | undefined, sources: { name: string; contents: string }[]): SarifLocations {
  if (!source) return {};
  const uri = (file: string) => {
    const path = relative(process.cwd(), source.input.kind === 'hcl' ? join(source.target, file) : file);
    return (path || file).split('\\').join('/');
  };
  if (source.input.kind !== 'hcl') return { uri };
  const texts = new Map(sources.map((s) => [s.name, s.contents]));
  const line = (file: string, f: Finding): number | undefined => {
    const text = texts.get(file);
    if (text === undefined) return undefined;
    const type = f.resource.type;
    const name = f.resource.address.slice(f.resource.address.lastIndexOf(`${type}.`) + type.length + 1);
    const at = locateResource(text, type, name);
    return at ? text.slice(0, at.range.start).split('\n').length : undefined;
  };
  return { uri, line };
}
