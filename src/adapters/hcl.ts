/* ============================================================================
   HCL → Resource[].

   The parser is injected: in Node it is @cdktf/hcl2json's `parse`, in the
   browser it is the same WebAssembly module behind a hand-written loader.
   Either way the input here is hcl2json's JSON shape:

     { resource: { aws_lb_listener: { https: [ { attr: value, block: [ {...} ] } ] } },
       module:   { alb: [ { source: "...", listeners: {...} } ] },
       variable: { ... }, data: { ... }, ... }

   Literal values are literals; any expression is the string "${...}". The
   predicate layer treats such strings as unknown, so this adapter only has to
   flag what hcl2json cannot represent at all: `dynamic` blocks, whose
   content is generated at plan time.
   ========================================================================= */

import type { AttrValue, Resource } from '../engine/types.ts';

export type HclParser = (filename: string, contents: string) => Promise<unknown>;

/* Things the scan saw but could not look inside. Reported, never silent. */
export type CoverageNote =
  | { kind: 'module-call'; address: string; file: string; source?: string }
  | { kind: 'dynamic-block'; address: string; file: string; block: string }
  | { kind: 'parse-error'; file: string; message: string };

export type HclScan = { resources: Resource[]; notes: CoverageNote[] };

type Json = { [k: string]: unknown };
const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);

export function resourcesFromHclJson(json: unknown, file: string): HclScan {
  const resources: Resource[] = [];
  const notes: CoverageNote[] = [];
  if (!isObj(json)) return { resources, notes };

  const resourceMap = json.resource;
  if (isObj(resourceMap)) {
    for (const [type, byName] of Object.entries(resourceMap)) {
      if (!isObj(byName)) continue;
      for (const [name, bodies] of Object.entries(byName)) {
        const address = `${type}.${name}`;
        const list = Array.isArray(bodies) ? bodies : [bodies];
        for (const body of list) {
          if (!isObj(body)) continue;
          const { attrs, unknown } = normaliseBody(body, address, file, notes);
          resources.push({ type, address, attrs, unknown, origin: { kind: 'hcl', file } });
        }
      }
    }
  }

  const moduleMap = json.module;
  if (isObj(moduleMap)) {
    for (const [name, bodies] of Object.entries(moduleMap)) {
      const list = Array.isArray(bodies) ? bodies : [bodies];
      for (const body of list) {
        const source = isObj(body) && typeof body.source === 'string' ? body.source : undefined;
        notes.push(source ? { kind: 'module-call', address: `module.${name}`, file, source } : { kind: 'module-call', address: `module.${name}`, file });
      }
    }
  }
  return { resources, notes };
}

function normaliseBody(body: Json, address: string, file: string, notes: CoverageNote[]): { attrs: Resource['attrs']; unknown: string[] } {
  const attrs: Resource['attrs'] = {};
  const unknown: string[] = [];
  for (const [key, value] of Object.entries(body)) {
    if (key === 'dynamic' && isObj(value)) {
      for (const block of Object.keys(value)) {
        unknown.push(block);
        notes.push({ kind: 'dynamic-block', address, file, block });
      }
      continue;
    }
    /* Meta-arguments describe how many copies exist, not what they contain. */
    if (key === 'count' || key === 'for_each' || key === 'provider' || key === 'depends_on' || key === 'lifecycle') continue;
    attrs[key] = value as AttrValue;
  }
  return { attrs, unknown };
}

export async function scanHclFiles(files: { name: string; contents: string }[], parse: HclParser): Promise<HclScan> {
  const out: HclScan = { resources: [], notes: [] };
  for (const f of files) {
    let json: unknown;
    try {
      json = await parse(f.name, f.contents);
    } catch (e) {
      out.notes.push({ kind: 'parse-error', file: f.name, message: (e as Error).message });
      continue;
    }
    const scan = resourcesFromHclJson(json, f.name);
    out.resources.push(...scan.resources);
    out.notes.push(...scan.notes);
  }
  return out;
}
