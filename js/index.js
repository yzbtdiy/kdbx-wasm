// KDBX password database parser for JavaScript
// Thin wrapper around the WebAssembly module

import * as wasm from './kdbx_wasm.js';

// Re-export all functions and classes
export const KdbxDatabase = wasm.KdbxDatabase;
export const isKdbxFile = wasm.isKdbxFile;
export const getFileInfo = wasm.getFileInfo;
export const start = wasm.start;
export const initSync = wasm.initSync;

// Re-export default (init function)
export { wasm as default };

/**
 * Initialize the WASM module with an optional module path.
 * This is a convenience wrapper around the default export.
 * @param {string|URL|Request|WebAssembly.Module} [module_or_path]
 */
export async function initKdbxWasm(module_or_path) {
    return wasm.default(module_or_path);
}
