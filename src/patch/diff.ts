/* Unified diff, written out: Myers' O(ND) shortest edit script over lines,
   grouped into hunks the way `diff -u` does. */

type Op = { t: ' ' | '-' | '+'; line: string };

/* Lines keep their terminator, so a missing final newline is a difference. */
const split = (s: string): string[] => s.match(/[^\n]*\n|[^\n]+$/g) ?? [];

function edits(a: string[], b: string[]): Op[] {
  const n = a.length, m = b.length, max = n + m, off = max + 1;
  const trace: Int32Array[] = [];
  let v = new Int32Array(2 * max + 3);
  let found = -1;
  for (let d = 0; d <= max && found < 0; d++) {
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && (v[off + k - 1] as number) < (v[off + k + 1] as number)) ? (v[off + k + 1] as number) : (v[off + k - 1] as number) + 1;
      let y = x - k;
      while (x < n && y < m && a[x] === b[y]) { x++; y++; }
      v[off + k] = x;
      if (x >= n && y >= m) { found = d; break; }
    }
    trace.push(v.slice());
  }
  const out: Op[] = [];
  let x = n, y = m;
  for (let d = found; d > 0; d--) {
    const p = trace[d - 1] as Int32Array, k = x - y;
    const prevK = k === -d || (k !== d && (p[off + k - 1] as number) < (p[off + k + 1] as number)) ? k + 1 : k - 1;
    const px = p[off + prevK] as number, py = px - prevK;
    const insert = prevK === k + 1;
    const mx = insert ? px : px + 1, my = insert ? py + 1 : py;
    while (x > mx && y > my) { out.push({ t: ' ', line: a[--x] as string }); y--; }
    if (insert) out.push({ t: '+', line: b[--y] as string });
    else out.push({ t: '-', line: a[--x] as string });
  }
  while (x > 0) { out.push({ t: ' ', line: a[--x] as string }); y--; }
  return out.reverse();
}

const range = (start: number, count: number): string => (count === 1 ? `${start}` : `${count === 0 ? start - 1 : start},${count}`);

export function unifiedDiff(oldText: string, newText: string, oldName: string, newName: string, context = 3): string {
  const ops = edits(split(oldText), split(newText));
  const changes = ops.flatMap((o, i) => (o.t === ' ' ? [] : [i]));
  if (changes.length === 0) return '';
  let out = `--- a/${oldName}\n+++ b/${newName}\n`;
  /* Changes closer than twice the context share a hunk. */
  let g = 0;
  while (g < changes.length) {
    let h = g;
    while (h + 1 < changes.length && (changes[h + 1] as number) - (changes[h] as number) <= 2 * context + 1) h++;
    const from = Math.max(0, (changes[g] as number) - context);
    const to = Math.min(ops.length, (changes[h] as number) + context + 1);
    let oldLine = 1, newLine = 1;
    for (const o of ops.slice(0, from)) { if (o.t !== '+') oldLine++; if (o.t !== '-') newLine++; }
    const body = ops.slice(from, to);
    const oldCount = body.filter((o) => o.t !== '+').length, newCount = body.filter((o) => o.t !== '-').length;
    out += `@@ -${range(oldLine, oldCount)} +${range(newLine, newCount)} @@\n`;
    for (const o of body) out += o.t + o.line + (o.line.endsWith('\n') ? '' : '\n\\ No newline at end of file\n');
    g = h + 1;
  }
  return out;
}
