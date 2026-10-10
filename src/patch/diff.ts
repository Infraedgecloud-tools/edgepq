/* ============================================================================
   Unified diff, written out.

   The inputs are always one Terraform file and the same file with a few
   attribute lines replaced or inserted, so the edit script is found by
   walking both line lists together and, at a mismatch, taking whichever of
   these resyncs soonest: replace r lines (a[i+r] == b[j+r]), delete k lines
   (a[i+k] == b[j]) or insert k lines (b[j+k] == a[i]). Beyond the window it
   is treated as a replacement of one line and the walk goes on. The result
   is always a valid edit script (every line of a is deleted or kept, every
   line of b is kept or inserted), which is what `git apply` needs; it is the
   shortest one for the edits this tool makes. Memory is one line array each.
   ========================================================================= */

type Op = { t: ' ' | '-' | '+'; line: string };

/* Lines keep their terminator, so a missing final newline is a difference. */
const split = (s: string): string[] => s.match(/[^\n]*\n|[^\n]+$/g) ?? [];

const WINDOW = 200;

export function edits(a: string[], b: string[]): Op[] {
  const out: Op[] = [];
  let i = 0, j = 0;
  while (i < a.length || j < b.length) {
    if (i >= a.length) { out.push({ t: '+', line: b[j++] as string }); continue; }
    if (j >= b.length) { out.push({ t: '-', line: a[i++] as string }); continue; }
    if (a[i] === b[j]) { out.push({ t: ' ', line: a[i] as string }); i++; j++; continue; }
    /* Smallest step that lands both sides on equal lines again. */
    let best: { kind: 'replace' | 'delete' | 'insert'; n: number } = { kind: 'replace', n: 1 };
    let bestCost = Infinity;
    for (let n = 1; n <= WINDOW; n++) {
      if (i + n < a.length && j + n < b.length && a[i + n] === b[j + n] && n < bestCost) { best = { kind: 'replace', n }; bestCost = n; break; }
      if (i + n < a.length && a[i + n] === b[j] && n < bestCost) { best = { kind: 'delete', n }; bestCost = n; break; }
      if (j + n < b.length && b[j + n] === a[i] && n < bestCost) { best = { kind: 'insert', n }; bestCost = n; break; }
    }
    if (best.kind === 'replace') {
      for (let n = 0; n < best.n; n++) out.push({ t: '-', line: a[i++] as string });
      for (let n = 0; n < best.n; n++) out.push({ t: '+', line: b[j++] as string });
    } else if (best.kind === 'delete') {
      for (let n = 0; n < best.n; n++) out.push({ t: '-', line: a[i++] as string });
    } else {
      for (let n = 0; n < best.n; n++) out.push({ t: '+', line: b[j++] as string });
    }
  }
  return out;
}

const range = (start: number, count: number): string => (count === 1 ? `${start}` : `${count === 0 ? start - 1 : start},${count}`);

/* The unchanged head and tail of the file are found by character compare
   and never split into lines: one small edit in a large file costs a scan,
   not an allocation per line. The cut points sit on line boundaries, with
   `context` whole lines kept on each side so the hunks read as usual. */
export type Changed = { start: number; end: number };

function trim(oldText: string, newText: string, context: number, changed?: Changed): { head: number; headLines: number; oldMid: string; newMid: string; tail: string } {
  const n = Math.min(oldText.length, newText.length);
  /* A caller that made the edits knows where they are; otherwise compare. */
  let p = changed ? Math.min(changed.start, n) : 0;
  while (p < n && oldText.charCodeAt(p) === newText.charCodeAt(p)) p++;
  /* Back up to a line start, then `context` more lines. */
  let head = oldText.lastIndexOf('\n', p - 1) + 1;
  for (let c = 0; c < context && head > 0; c++) head = oldText.lastIndexOf('\n', head - 2) + 1;
  let s = changed ? Math.max(0, Math.min(oldText.length - changed.end, n - head)) : 0;
  while (s < n - head && oldText.charCodeAt(oldText.length - 1 - s) === newText.charCodeAt(newText.length - 1 - s)) s++;
  /* Forward to a line end (the shared tail must start after a newline), then `context` more lines. */
  let tailStart = oldText.length - s;
  tailStart = oldText.indexOf('\n', tailStart);
  tailStart = tailStart < 0 ? oldText.length : tailStart + 1;
  for (let c = 0; c < context && tailStart < oldText.length; c++) { const nl = oldText.indexOf('\n', tailStart); tailStart = nl < 0 ? oldText.length : nl + 1; }
  const tailLen = oldText.length - tailStart;
  let headLines = 0;
  for (let i = 0; i < head; i++) if (oldText.charCodeAt(i) === 10) headLines++;
  return { head, headLines, oldMid: oldText.slice(head, oldText.length - tailLen), newMid: newText.slice(head, newText.length - tailLen), tail: oldText.slice(tailStart) };
}

export function unifiedDiff(oldText: string, newText: string, oldName: string, newName: string, context = 3, changed?: Changed): string {
  if (oldText === newText) return '';
  const t = trim(oldText, newText, context, changed);
  const ops = edits(split(t.oldMid), split(t.newMid));
  const changes = ops.flatMap((o, i) => (o.t === ' ' ? [] : [i]));
  if (changes.length === 0) return '';
  let out = `--- a/${oldName}\n+++ b/${newName}\n`;
  /* Changes closer than twice the context share a hunk. Line numbers are
     carried forward rather than recounted from the start for every hunk. */
  let g = 0;
  let counted = 0, oldLine = t.headLines + 1, newLine = t.headLines + 1;
  while (g < changes.length) {
    let h = g;
    while (h + 1 < changes.length && (changes[h + 1] as number) - (changes[h] as number) <= 2 * context + 1) h++;
    const from = Math.max(0, (changes[g] as number) - context);
    const to = Math.min(ops.length, (changes[h] as number) + context + 1);
    for (; counted < from; counted++) { const o = ops[counted] as Op; if (o.t !== '+') oldLine++; if (o.t !== '-') newLine++; }
    const body = ops.slice(from, to);
    const oldCount = body.filter((o) => o.t !== '+').length, newCount = body.filter((o) => o.t !== '-').length;
    out += `@@ -${range(oldLine, oldCount)} +${range(newLine, newCount)} @@\n`;
    for (const o of body) out += o.t + o.line + (o.line.endsWith('\n') ? '' : '\n\\ No newline at end of file\n');
    g = h + 1;
  }
  /* Copy out of V8's sliced strings: the lines above are views onto the
     whole new text, and a thousand small diffs would otherwise keep a
     thousand copies of the file alive. */
  return Buffer.from(out, 'utf8').toString('utf8');
}
