/* ============================================================================
   HCL → Resource[].

   The parser is injected: in Node it is @cdktf/hcl2json's `parse`, in the
   browser it is the same WebAssembly module behind a hand-written loader.
   Either way the input here is hcl2json's JSON shape:

     { resource: { aws_lb_listener: { https: [ { attr: value, block: [ {...} ] } ] } },
       module:   { alb: [ { source: "...", listeners: {...} } ] },
       variable: { ... }, locals: [ { ... } ], data: { ... }, ... }

   Literal values are literals; any expression is the string "${...}". The
   predicate layer treats such strings as unknown, so this adapter only has to
   flag what hcl2json cannot represent at all: `dynamic` blocks, whose
   content is generated at plan time.

   Two references are resolved here, because they are the commonest shape in
   real code and the answer is in the files: a whole-value `var.x` becomes
   the value the module was called with, or the variable's default, and a
   whole-value `local.x` becomes the local's literal. A default is an
   assumption and is noted as one; a plan may pass something else.
   ========================================================================= */

import type { AttrValue, Resource } from '../engine/types.ts';

export type HclParser = (filename: string, contents: string) => Promise<unknown>;

/* Things the scan saw but could not look inside, or had to assume. Reported,
   never silent. */
export type CoverageNote =
  | { kind: 'module-call'; address: string; file: string; source?: string; scanned?: boolean }
  | { kind: 'dynamic-block'; address: string; file: string; block: string }
  | { kind: 'count-zero'; address: string; file: string }
  | { kind: 'count-expression'; address: string; file: string; meta: 'count' | 'for_each' }
  | { kind: 'default-used'; address: string; file: string; attr: string; variable: string }
  | { kind: 'parse-error'; file: string; message: string };

/* A `module` block: where it points and what it passes in. */
export type ModuleCall = { name: string; file: string; source?: string; inputs: Record<string, AttrValue>; repeated: boolean };

export type HclScan = {
  resources: Resource[];
  notes: CoverageNote[];
  modules: ModuleCall[];
  variables: Record<string, AttrValue | undefined>;
  locals: Record<string, AttrValue>;
};

/* How a set of files is read: the address prefix of the module they form
   ("" for the root, "module.alb." for a call, "modules/alb:" for a directory
   nobody calls) and the values a call passed in. */
export type ScanContext = { prefix?: string; inputs?: Record<string, AttrValue> };

type Json = { [k: string]: unknown };
const isObj = (v: unknown): v is Json => typeof v === 'object' && v !== null && !Array.isArray(v);
const META = new Set(['count', 'for_each', 'provider', 'depends_on', 'lifecycle']);
const MODULE_META = new Set(['source', 'version', 'count', 'for_each', 'providers', 'depends_on']);

export function resourcesFromHclJson(json: unknown, file: string, ctx: ScanContext = {}): HclScan {
  const prefix = ctx.prefix ?? '';
  const scan: HclScan = { resources: [], notes: [], modules: [], variables: {}, locals: {} };
  if (!isObj(json)) return scan;

  const resourceMap = json.resource;
  if (isObj(resourceMap)) {
    for (const [type, byName] of Object.entries(resourceMap)) {
      if (!isObj(byName)) continue;
      for (const [name, bodies] of Object.entries(byName)) {
        const address = `${prefix}${type}.${name}`;
        const list = Array.isArray(bodies) ? bodies : [bodies];
        for (const body of list) {
          if (!isObj(body)) continue;
          /* `count = 0` is the usual way to switch a resource off; nothing is created. */
          if (body.count === 0) { scan.notes.push({ kind: 'count-zero', address, file }); continue; }
          /* Any other count or for_each decides at plan time how many exist, and
             whether any do; the body is checked as written and the note says so. */
          if ('count' in body) scan.notes.push({ kind: 'count-expression', address, file, meta: 'count' });
          if ('for_each' in body) scan.notes.push({ kind: 'count-expression', address, file, meta: 'for_each' });
          const { attrs, unknown } = normaliseBody(body, address, file, scan.notes);
          const ignore = ignoreChanges(body);
          scan.resources.push({ type, address, attrs, unknown, origin: { kind: 'hcl', file }, ...(ignore ? { ignore_changes: ignore } : {}) });
        }
      }
    }
  }

  const moduleMap = json.module;
  if (isObj(moduleMap)) {
    for (const [name, bodies] of Object.entries(moduleMap)) {
      const list = Array.isArray(bodies) ? bodies : [bodies];
      for (const body of list) {
        if (!isObj(body)) continue;
        const source = typeof body.source === 'string' ? body.source : undefined;
        const inputs: Record<string, AttrValue> = {};
        for (const [k, v] of Object.entries(body)) if (!MODULE_META.has(k)) inputs[k] = v as AttrValue;
        scan.modules.push({ name, file, ...(source !== undefined ? { source } : {}), inputs, repeated: 'count' in body || 'for_each' in body });
      }
    }
  }

  const variableMap = json.variable;
  if (isObj(variableMap)) {
    for (const [name, bodies] of Object.entries(variableMap)) {
      const body = Array.isArray(bodies) ? bodies[0] : bodies;
      scan.variables[name] = isObj(body) && 'default' in body ? (body.default as AttrValue) : undefined;
    }
  }
  const localsList = json.locals;
  for (const block of Array.isArray(localsList) ? localsList : localsList === undefined ? [] : [localsList]) {
    if (!isObj(block)) continue;
    for (const [k, v] of Object.entries(block)) scan.locals[k] = v as AttrValue;
  }
  return scan;
}

/* `lifecycle { ignore_changes = [ssl_policy] }` arrives as ["${ssl_policy}"]
   (hcl2json renders the references as expressions); `all` as ["all"]. */
function ignoreChanges(body: Json): string[] | undefined {
  const lifecycle = Array.isArray(body.lifecycle) ? body.lifecycle[0] : body.lifecycle;
  if (!isObj(lifecycle)) return undefined;
  const list = lifecycle.ignore_changes;
  if (typeof list === 'string') return list.includes('all') ? ['all'] : undefined;
  if (!Array.isArray(list)) return undefined;
  const names = list.filter((x): x is string => typeof x === 'string').map((x) => x.replace(/^\$\{(.*)\}$/, '$1'));
  return names.length ? names : undefined;
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
    if (META.has(key)) continue;
    attrs[key] = value as AttrValue;
  }
  return { attrs, unknown };
}

/* ------------------------------------------------------------ resolution */

const VAR_REF = /^\$\{var\.([A-Za-z0-9_-]+)\}$/;
const LOCAL_REF = /^\$\{local\.([A-Za-z0-9_-]+)\}$/;
const isLiteral = (v: unknown): v is AttrValue => v !== undefined && !(typeof v === 'string' && v.startsWith('${'));

/* Replace whole-value var.x and local.x references in every resource of one
   module with what is known: the call's inputs first, then the variable's
   default (noted as an assumption), then a literal local. A reference that
   cannot be resolved stays an expression and the engine treats it as unknown. */
export function bindReferences(scan: HclScan, inputs: Record<string, AttrValue>): void {
  const resolve = (value: unknown, address: string, file: string, path: string): unknown => {
    if (typeof value === 'string') {
      const v = VAR_REF.exec(value);
      if (v) {
        const name = v[1] as string;
        if (name in inputs && isLiteral(inputs[name])) return inputs[name];
        const def = scan.variables[name];
        if (isLiteral(def)) {
          scan.notes.push({ kind: 'default-used', address, file, attr: path, variable: name });
          return def;
        }
        return value;
      }
      const l = LOCAL_REF.exec(value);
      if (l) {
        const lit = scan.locals[l[1] as string];
        return isLiteral(lit) ? lit : value;
      }
      return value;
    }
    if (Array.isArray(value)) return value.map((item, i) => resolve(item, address, file, `${path}[${i}]`));
    if (isObj(value)) {
      const out: Json = {};
      for (const [k, v] of Object.entries(value)) out[k] = resolve(v, address, file, path ? `${path}.${k}` : k);
      return out;
    }
    return value;
  };
  for (const r of scan.resources) {
    r.attrs = resolve(r.attrs, r.address, r.origin.kind === 'hcl' ? r.origin.file : '', '') as Resource['attrs'];
  }
  for (const m of scan.modules) {
    m.inputs = resolve(m.inputs, `${m.name}`, m.file, '') as Record<string, AttrValue>;
  }
}

/* The files of one module, read together: variables and locals in one file
   apply to resources in another. */
export async function scanHclFiles(files: { name: string; contents: string }[], parse: HclParser, ctx: ScanContext = {}): Promise<HclScan> {
  const out: HclScan = { resources: [], notes: [], modules: [], variables: {}, locals: {} };
  for (const f of files) {
    let json: unknown;
    try {
      json = await parse(f.name, f.contents);
    } catch (e) {
      out.notes.push({ kind: 'parse-error', file: f.name, message: (e as Error).message });
      continue;
    }
    const scan = resourcesFromHclJson(json, f.name, ctx);
    out.resources.push(...scan.resources);
    out.notes.push(...scan.notes);
    out.modules.push(...scan.modules);
    Object.assign(out.variables, scan.variables);
    Object.assign(out.locals, scan.locals);
  }
  bindReferences(out, ctx.inputs ?? {});
  for (const m of out.modules) {
    out.notes.push({ kind: 'module-call', address: `${ctx.prefix ?? ''}module.${m.name}`, file: m.file, ...(m.source !== undefined ? { source: m.source } : {}) });
  }
  return out;
}
