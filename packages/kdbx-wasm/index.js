// Node.js ESM entry for kdbx-wasm.
//
// Loads the WASM module synchronously from disk on import, so no init call
// is needed on Node.js. Browsers and bundlers resolve the "default" exports
// condition to ./kdbx_wasm.js instead, whose fetch-based init they await:
//
//   import init, { KdbxDatabase } from 'kdbx-wasm';
//   await init();

import { readFileSync } from 'node:fs';
import { initSync } from './kdbx_wasm.js';

initSync({
    module: new WebAssembly.Module(
        readFileSync(new URL('./kdbx_wasm_bg.wasm', import.meta.url))
    ),
});

export * from './kdbx_wasm.js';
