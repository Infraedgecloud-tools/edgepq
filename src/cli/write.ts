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

export type Written = { files: string[]; patches: number; patchesSkipped: { ruleId: string; address: string; reason: string }[]; perFixFilesOmitted?: boolean };

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
  const written: Written = { files, patches: 0, patchesSkipped: [] };

  /* Patches first, so the fixes that could not be written are in the report. */
  let patches: ReturnType<typeof buildPatchesWithSkips>['patches'] = [];
  if (source && source.input.kind === 'hcl' && report.input.kind === 'hcl') {
    const sources = await Promise.all(source.input.files.map(async (name) => ({ name, contents: await readFile(join(source.target, name), 'utf8') })));
    const built = buildPatchesWithSkips(report.findings, sources);
    patches = built.patches;
    written.patchesSkipped = built.skipped.map((s) => ({ ruleId: s.ruleId, address: s.address, reason: s.reason }));
    if (written.patchesSkipped.length) report.input.patches_skipped = written.patchesSkipped;
  }

  await put(OUTPUT_NAMES.json, renderJson(report));
  await put(OUTPUT_NAMES.markdown, renderMarkdown(report));
  await put(OUTPUT_NAMES.html, renderHtml(report));
  await put(OUTPUT_NAMES.cbom, renderCbomJson(report));
  if (patches.length === 0) return written;
  await mkdir(join(outDir, OUTPUT_NAMES.patchesDir), { recursive: true });
  /* One file per fix is useful up to a point; past it the combined patches
     and the JSON carry the same information without a thousand files. */
  const PER_FIX_LIMIT = 200;
  written.patches = patches.length;
  if (patches.length <= PER_FIX_LIMIT) {
    for (const p of patches) {
      const name = `${OUTPUT_NAMES.patchesDir}/${p.ruleId}-${p.address.replace(/[^A-Za-z0-9_.-]+/g, '_')}.patch`;
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
