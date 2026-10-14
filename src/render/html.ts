/* One self-contained file: inline style, no scripts, no fonts, no images, no
   requests. The only URLs are the source links, which are anchors the reader
   chooses to follow. Every value that came from a finding is escaped. */
import { buildDoc, type FindingView } from './document.ts';
import type { ScanReport } from './types.ts';

export const esc = (s: string): string =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const CSS = `
:root{--navy-900:#0B2545;--sky-700:#1A63B0;--gold-400:#F5C242;--slate-500:#5B6B85;--line:#DDE5EF;--mist:#F2F6FB;--base:#F7F9FC;--white:#FFFFFF;
--ink:var(--navy-900);--link:var(--sky-700);--muted:#4A5A75;--card:var(--white);--code:var(--mist);
--sev-critical-bg:#8A1C1C;--sev-high-bg:#B4410A;--sev-medium-bg:#FCE9B0;--sev-medium-fg:#4D3600;--sev-low-bg:#DCE6F2;--sev-low-fg:#0B2545;--sev-info-bg:#E8EDF4;--sev-info-fg:#3C4A63;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--navy-900:#E8EEF7;--sky-700:#7FB4F0;--slate-500:#9AA9C2;--line:#27406A;--mist:#10294D;--base:#071A33;--white:#0B2545;
--ink:#E8EEF7;--link:#7FB4F0;--muted:#A9B7CD;--card:#0B2545;--code:#10294D;
--sev-critical-bg:#F2A0A0;--sev-high-bg:#F5B88A;--sev-medium-bg:#5C4710;--sev-medium-fg:#FCE9B0;--sev-low-bg:#27406A;--sev-low-fg:#DCE6F2;--sev-info-bg:#1B3558;--sev-info-fg:#C9D5E6}}
*{box-sizing:border-box}
body{margin:0;background:var(--base);color:var(--ink);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:56rem;margin:0 auto;padding:1.5rem 16px 3rem}
h1{font-size:1.6rem;line-height:1.25;margin:0 0 .5rem;border-top:6px solid var(--gold-400);padding-top:1rem}
h2{font-size:1.2rem;margin:2.2rem 0 .8rem;color:var(--link)}
h3{font-size:1rem;margin:0 0 .4rem;overflow-wrap:anywhere}
a{color:var(--link)}.scope,.muted{color:var(--muted)}
article{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:1rem;margin:0 0 1rem}
.badge{display:inline-block;font-size:.8rem;font-weight:600;padding:.05rem .5rem;border-radius:3px;margin-right:.4rem}
.badge.critical,.badge.high{color:#fff}.badge.critical{background:var(--sev-critical-bg)}.badge.high{background:var(--sev-high-bg)}
.badge.medium{background:var(--sev-medium-bg);color:var(--sev-medium-fg)}.badge.low{background:var(--sev-low-bg);color:var(--sev-low-fg)}.badge.info{background:var(--sev-info-bg);color:var(--sev-info-fg)}
@media (prefers-color-scheme:dark){.badge.critical,.badge.high{color:#1a0a0a}}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{text-align:left;padding:.35rem .6rem;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}th{color:var(--slate-500);font-weight:600}
pre{background:var(--code);padding:.6rem .8rem;border-radius:4px;overflow-x:auto;margin:.5rem 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.88rem}
ul{padding-left:1.2rem}li{overflow-wrap:anywhere}
`;

function finding(f: FindingView): string {
  const rows = f.observed.map((o) => `<tr><td>${esc(o.attr)}</td><td>${esc(o.value)}${o.defaulted ? ' <span class="muted">(defaulted)</span>' : ''}</td></tr>`).join('');
  return `<article><h3>${esc(f.heading)}</h3>
<p><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span><span class="muted">${esc(f.category)}</span></p>
<p>${esc(f.message)}</p>
${rows ? `<div class="scroll"><table><thead><tr><th>Attribute</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table></div>` : ''}
${f.fix.code.length || f.fix.text.length ? `<p><strong>Fix</strong></p>${f.fix.code.length ? `<pre><code>${esc(f.fix.code.join('\n'))}</code></pre>` : ''}${f.fix.text.map((t) => `<p>${esc(t)}</p>`).join('')}` : ''}
${f.sources.length ? `<p><strong>Sources</strong></p><ul>${f.sources.map((s) => `<li><a href="${esc(s.url)}" rel="noopener noreferrer">${esc(s.url)}</a> (verified ${esc(s.verified)})</li>`).join('')}</ul>` : ''}</article>`;
}

export function renderHtml(report: ScanReport): string {
  const d = buildDoc(report);
  const notCovered = d.coverage.find((c) => c.label === 'Not covered')!;
  const list = (items: string[]) => `<ul>${items.map((i) => `<li>${esc(i)}</li>`).join('')}</ul>`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(d.title)}</title><style>${CSS}</style></head><body><main>
<h1>${esc(d.title)}</h1><p class="scope">${esc(d.scope)}</p>
<h2>What this report does and does not say</h2><p>${esc(d.intro.join(' '))}</p>${list(notCovered.items)}
${d.groups.map((g) => `<h2>Findings: ${esc(g.label)} (${g.findings.length})</h2>${g.findings.map(finding).join('\n') || '<p class="muted">None.</p>'}`).join('\n')}
<h2>Coverage</h2>${d.coverage.filter((c) => c.items.length).map((c) => `<p><strong>${esc(c.label)}</strong></p>${list(c.items)}`).join('')}
<h2>Rules run</h2><div class="scroll"><table><thead><tr><th>Rule</th><th>Version</th><th>Title</th><th>Category</th><th>Severity</th><th>Sources</th></tr></thead><tbody>${d.rules.map((r) => `<tr><td>${esc(r.id)}</td><td>${r.version}</td><td>${esc(r.title)}</td><td>${esc(r.category)}</td><td>${esc(r.severity)}</td><td>${r.sources}</td></tr>`).join('')}</tbody></table></div>
</main></body></html>
`;
}
