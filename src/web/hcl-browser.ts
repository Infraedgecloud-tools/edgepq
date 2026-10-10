/* ============================================================================
   The HCL parser in the browser: HashiCorp's hcl2json compiled from Go to
   WebAssembly, the same module the CLI uses. The Go runtime shim
   (wasm_exec.js, bundled as a side effect) defines `globalThis.Go`; the
   program registers its functions on the object we hand it before `run`.
   ========================================================================= */

import '@cdktf/hcl2json/wasm/wasm_exec.js';
import type { HclParser } from '../adapters/hcl.ts';

type GoRuntime = { importObject: WebAssembly.Imports; run(instance: WebAssembly.Instance): Promise<void> };
type Bridge = { parse?: (filename: string, contents: string, cb: (err: string | null, out?: string) => void) => void };

declare global {
  // eslint-disable-next-line no-var
  var Go: new () => GoRuntime;
  // eslint-disable-next-line no-var
  var __parse_terraform_config_wasm__: Bridge | undefined;
}

let loading: Promise<Bridge> | undefined;

/* Fetch and start the module once. `url` is the wasm file beside the bundle. */
export function loadHclParser(url: string): Promise<Bridge> {
  if (loading) return loading;
  loading = (async () => {
    const go = new globalThis.Go();
    const bridge: Bridge = {};
    /* The Go program looks for its bridge object on `global`, Node's name for
       the global object; a browser has only `globalThis`. */
    const g = globalThis as typeof globalThis & { global?: typeof globalThis };
    if (!g.global) g.global = globalThis;
    globalThis.__parse_terraform_config_wasm__ = bridge;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`could not fetch ${url}: HTTP ${response.status}`);
    /* instantiateStreaming needs the right content type; the fallback does not. */
    let instance: WebAssembly.Instance;
    try {
      instance = (await WebAssembly.instantiateStreaming(response.clone(), go.importObject)).instance;
    } catch {
      instance = (await WebAssembly.instantiate(await response.arrayBuffer(), go.importObject)).instance;
    }
    void go.run(instance);
    /* The Go main registers `parse` asynchronously after run; wait for it. */
    for (let i = 0; i < 2000 && typeof bridge.parse !== 'function'; i++) await new Promise((r) => setTimeout(r, 5));
    if (typeof bridge.parse !== 'function') throw new Error('the HCL parser did not start');
    return bridge;
  })();
  return loading;
}

export function browserHclParser(url: string): HclParser {
  return async (filename, contents) => {
    const bridge = await loadHclParser(url);
    const out = await new Promise<string>((resolve, reject) => {
      bridge.parse!(filename, contents, (err, result) => (err ? reject(new Error(err)) : resolve(result ?? '{}')));
    });
    return JSON.parse(out) as unknown;
  };
}
