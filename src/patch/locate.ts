/* ============================================================================
   Find resources and attributes in HCL source text without a parser.

   A small scanner knows the four things that can hide a brace or a keyword:
   strings (with ${} and %{} interpolation, which nest), heredocs, and line and
   block comments. Everything else is structure: `name = value` lines and
   `name "label" { ... }` blocks. Strings in, offsets out; no Node modules.
   ========================================================================= */

export type Range = { start: number; end: number };
export type ResourceLocation = { range: Range; body: Range; duplicate: boolean };
export type AttrLocation =
  | { kind: 'literal-string'; valueRange: Range; line: number }
  | { kind: 'present-not-literal' }
  /* `align` is the column of `=` in the neighbouring attributes when they are aligned. */
  | { kind: 'absent'; insertAt: number; indent: string; align?: number }
  | { kind: 'ambiguous'; reason: string };

/* ---------------------------------------------------------------- scanner */

function skipInterpolation(t: string, i: number): number {
  let depth = 1;
  while (i < t.length) {
    const c = t[i];
    if (c === '"') { i = skipString(t, i).end; continue; }
    if (c === '{') depth++;
    else if (c === '}' && --depth === 0) return i + 1;
    i++;
  }
  return i;
}

/* `t[i]` is the opening quote. `interp` is true when the string holds a live ${} or %{}. */
export function skipString(t: string, i: number): { end: number; interp: boolean } {
  let interp = false;
  i++;
  while (i < t.length) {
    const c = t[i];
    if (c === '\\') { i += 2; continue; }
    if (c === '"') return { end: i + 1, interp };
    if ((c === '$' || c === '%') && t[i + 1] === c && t[i + 2] === '{') { i += 3; continue; } /* $${ is a literal */
    if ((c === '$' || c === '%') && t[i + 1] === '{') { interp = true; i = skipInterpolation(t, i + 2); continue; }
    i++;
  }
  return { end: i, interp };
}

function skipHeredoc(t: string, i: number): number {
  const m = /<<-?([A-Za-z_][\w-]*)[ \t]*\r?\n/y;
  m.lastIndex = i;
  const hit = m.exec(t);
  if (!hit) return i;
  let pos = m.lastIndex;
  while (pos < t.length) {
    const nl = t.indexOf('\n', pos);
    const lineEnd = nl < 0 ? t.length : nl;
    if (t.slice(pos, lineEnd).trim() === hit[1]) return lineEnd;
    pos = lineEnd + 1;
  }
  return t.length;
}

/* If a string, comment or heredoc starts at `i`, the index after it; else `i`. */
function skipOpaque(t: string, i: number): number {
  const c = t[i];
  if (c === '"') return skipString(t, i).end;
  if (c === '#' || (c === '/' && t[i + 1] === '/')) { const n = t.indexOf('\n', i); return n < 0 ? t.length : n; }
  if (c === '/' && t[i + 1] === '*') { const n = t.indexOf('*/', i + 2); return n < 0 ? t.length : n + 2; }
  if (c === '<' && t[i + 1] === '<') return skipHeredoc(t, i);
  return i;
}

/* Index of the `}` matching the `{` at `open`, or -1. */
function matchBrace(t: string, open: number): number {
  let depth = 0;
  for (let i = open; i < t.length; ) {
    const o = skipOpaque(t, i);
    if (o !== i) { i = o; continue; }
    if (t[i] === '{') depth++;
    else if (t[i] === '}' && --depth === 0) return i;
    i++;
  }
  return -1;
}

/* -------------------------------------------------------------- structure */

type Attr = { kind: 'attr'; name: string; start: number; end: number; eq: number };
type Block = { kind: 'block'; name: string; labels: string[]; start: number; end: number; body: Range };
type Item = Attr | Block;

const lineNumber = (t: string, i: number): number => { let n = 1; for (let k = 0; k < i; k++) if (t.charCodeAt(k) === 10) n++; return n; };
const lineStart = (t: string, i: number): number => t.lastIndexOf('\n', i - 1) + 1;
const nextLine = (t: string, i: number): number => { const n = t.indexOf('\n', i); return n < 0 ? t.length : n; };

function items(t: string, r: Range): Item[] {
  const out: Item[] = [];
  const ident = /[A-Za-z_][\w-]*/y;
  let i = r.start;
  while (i < r.end) {
    if (/\s/.test(t[i] as string)) { i++; continue; }
    const o = skipOpaque(t, i);
    if (o !== i) { i = o; continue; }
    ident.lastIndex = i;
    const m = ident.exec(t);
    if (!m) { i = nextLine(t, i); continue; }
    const start = i;
    let j = ident.lastIndex;
    while (t[j] === ' ' || t[j] === '\t') j++;
    if (t[j] === '=' && t[j + 1] !== '=') {
      let k = j + 1, depth = 0;
      while (k < r.end) {
        const s = skipOpaque(t, k);
        if (s !== k) { k = s; continue; }
        const c = t[k] as string;
        if (c === '\n' && depth <= 0) break;
        if ('([{'.includes(c)) depth++;
        else if (')]}'.includes(c)) depth--;
        k++;
      }
      out.push({ kind: 'attr', name: m[0], start, end: k, eq: j });
      i = k;
      continue;
    }
    const labels: string[] = [];
    for (;;) {
      while (t[j] === ' ' || t[j] === '\t') j++;
      if (t[j] === '"') { const s = skipString(t, j); labels.push(t.slice(j + 1, s.end - 1)); j = s.end; continue; }
      ident.lastIndex = j;
      const l = ident.exec(t);
      if (!l) break;
      labels.push(l[0]);
      j = ident.lastIndex;
    }
    if (t[j] !== '{') { i = nextLine(t, j); continue; }
    const close = matchBrace(t, j);
    if (close < 0) break;
    out.push({ kind: 'block', name: m[0], labels, start, end: close + 1, body: { start: j + 1, end: close } });
    i = close + 1;
  }
  return out;
}

/* ----------------------------------------------------------------- public */

/* The top-level index of a file is asked for once per fix in that file.
   Planning every fix against the same original text means the same string
   comes back each time, so one entry is enough. */
let indexed: { text: string; items: Item[] } | undefined;
function topLevel(text: string): Item[] {
  if (!indexed || indexed.text !== text) indexed = { text, items: items(text, { start: 0, end: text.length }) };
  return indexed.items;
}

export function locateResource(text: string, type: string, name: string): ResourceLocation | undefined {
  const hits = topLevel(text).filter(
    (it): it is Block => it.kind === 'block' && it.name === 'resource' && it.labels[0] === type && it.labels[1] === name,
  );
  const first = hits[0];
  if (!first) return undefined;
  return { range: { start: first.start, end: first.end }, body: first.body, duplicate: hits.length > 1 };
}

export function locateAttribute(text: string, body: Range & { duplicate?: boolean }, path: string): AttrLocation {
  if (body.duplicate) return { kind: 'ambiguous', reason: 'the resource is defined more than once in this file' };
  const segments = path.split('.');
  const leaf = segments.pop() as string;
  let cur: Range = body;
  for (const seg of segments) {
    const all = items(text, cur);
    if (all.some((it) => it.kind === 'block' && it.name === 'dynamic' && it.labels[0] === seg)) {
      return { kind: 'ambiguous', reason: `${seg} is generated by a dynamic block` };
    }
    const blocks = all.filter((it): it is Block => it.kind === 'block' && it.name === seg);
    if (blocks.length !== 1) return { kind: 'ambiguous', reason: blocks.length === 0 ? `block ${seg} is not in the file` : `block ${seg} occurs ${blocks.length} times` };
    cur = (blocks[0] as Block).body;
  }
  const all = items(text, cur);
  const found = all.filter((it): it is Attr => it.kind === 'attr' && it.name === leaf);
  if (found.length > 1) return { kind: 'ambiguous', reason: `${leaf} is set more than once` };
  const attr = found[0];
  if (attr) {
    let vs = attr.eq + 1;
    while (text[vs] === ' ' || text[vs] === '\t') vs++;
    if (text[vs] !== '"') return { kind: 'present-not-literal' };
    const s = skipString(text, vs);
    const rest = text.slice(s.end, attr.end).trim();
    if (s.interp || (rest !== '' && !/^(#|\/\/|\/\*.*\*\/$)/.test(rest))) return { kind: 'present-not-literal' };
    return { kind: 'literal-string', valueRange: { start: vs, end: s.end }, line: lineNumber(text, vs) };
  }
  return locateInsertion(text, cur, all);
}

function locateInsertion(t: string, body: Range, all: Item[]): AttrLocation {
  if (!t.slice(body.start, body.end).includes('\n')) return { kind: 'ambiguous', reason: 'the block body is on one line' };
  const attrs = all.filter((it): it is Attr => it.kind === 'attr');
  const last = attrs.at(-1);
  const indentOf = (at: number) => t.slice(lineStart(t, at), at);
  if (last && !all.some((it) => it.kind === 'block' && it.start < last.start)) {
    const insertAt = nextLine(t, last.end) + 1;
    if (insertAt > body.end) return { kind: 'ambiguous', reason: 'the last attribute shares a line with the closing brace' };
    /* Aligned when the trailing run of consecutive-line attributes all put `=` in one column with padding. */
    const run: Attr[] = [last];
    for (let k = attrs.length - 2; k >= 0; k--) {
      const prev = attrs[k] as Attr;
      const gap = t.slice(prev.end, (run[0] as Attr).start);
      if (!/^[ \t]*\n[ \t]*$/.test(gap)) break;
      run.unshift(prev);
    }
    const cols = run.map((a) => a.eq - lineStart(t, a.start));
    const padded = run.some((a) => /\s\s/.test(t.slice(a.eq - 2, a.eq)));
    const aligned = run.length > 1 && padded && cols.every((c) => c === cols[0]);
    return aligned ? { kind: 'absent', insertAt, indent: indentOf(last.start), align: cols[0] as number } : { kind: 'absent', insertAt, indent: indentOf(last.start) };
  }
  const ls = lineStart(t, body.end);
  if (t.slice(ls, body.end).trim() !== '') return { kind: 'ambiguous', reason: 'the closing brace shares a line with other text' };
  const first = all[0];
  return { kind: 'absent', insertAt: ls, indent: first ? indentOf(first.start) : indentOf(body.end) + '  ' };
}
