/* Write every output of a scan into one directory. Returns what was written
   so the console summary and the tests can say so. */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { renderJson } from '../render/json.ts';
import { renderMarkdown } from '../render/markdown.ts';
import { renderHtml } from '../render/html.ts';
import { renderCbomJson } from '../render/cbom.ts';
import { buildPatchesWithSkips, combinePatches } from '../patch/index.ts';
import type { ScanReport } from '../render/types.ts';
import type { TerraformInput } from '../node/read-terraform.ts';

export type Written = { files: string[]; patches: number; patchesSkipped: { ruleId: string; address: string; reason: string }[] };

export const OUTPUT_NAMES = {
  json: 'edgepq-findings.json',
  markdown: 'edgepq-report.md',
  html: 'edgepq-report.html',
  cbom: 'edgepq-cbom.cdx.json',
  patchesDir: 'patches',
  autoPatch: 'edgepq-auto.patch',
  allPatch: 'edgepq-all.patch',
};

export async function writeOutputs(report: ScanReport, outDir: string, source?: { target: string; input: TerraformInput }): Promise<Written> {
  await mkdir(outDir, { recursive: true });
  const files: string[] = [];
  const put = async (name: string, contents: string) => {
    await writeFile(join(outDir, name), contents);
    files.push(name);
  };
  await put(OUTPUT_NAMES.json, renderJson(report));
  await put(OUTPUT_NAMES.markdown, renderMarkdown(report));
  await put(OUTPUT_NAMES.html, renderHtml(report));
  await put(OUTPUT_NAMES.cbom, renderCbomJson(report));

  const written: Written = { files, patches: 0, patchesSkipped: [] };
  if (!source || source.input.kind !== 'hcl') return written;

  /* Patches need the source text, under the names the adapter used. */
  const sources = await Promise.all(source.input.files.map(async (name) => ({ name, contents: await readFile(join(source.target, name), 'utf8') })));
  const { patches, skipped } = buildPatchesWithSkips(report.findings, sources);
  written.patchesSkipped = skipped.map((s) => ({ ruleId: s.ruleId, address: s.address, reason: s.reason }));
  if (patches.length === 0) return written;
  await mkdir(join(outDir, OUTPUT_NAMES.patchesDir), { recursive: true });
  for (const p of patches) {
    const name = `${OUTPUT_NAMES.patchesDir}/${p.ruleId}-${p.address.replace(/[^A-Za-z0-9_.-]+/g, '_')}.patch`;
    await put(name, p.diff);
    written.patches += 1;
  }
  const auto = combinePatches(patches, { safety: 'auto' });
  if (auto.included.length) await put(`${OUTPUT_NAMES.patchesDir}/${OUTPUT_NAMES.autoPatch}`, auto.diff);
  const all = combinePatches(patches, { safety: 'all' });
  if (all.included.length) await put(`${OUTPUT_NAMES.patchesDir}/${OUTPUT_NAMES.allPatch}`, all.diff);
  return written;
}
