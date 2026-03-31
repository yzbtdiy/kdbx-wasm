// KDBX password database parser for JavaScript
// This is a thin wrapper around the WebAssembly module

import * as wasm from './kdbx_wasm.js';

// Re-export all functions and classes
export const KdbxDatabase = wasm.KdbxDatabase;
export const isKdbxFile = wasm.isKdbxFile;
export const getFileInfo = wasm.getFileInfo;
export const start = wasm.start;

// Default export for convenience
export default {
  KdbxDatabase,
  isKdbxFile,
  getFileInfo,
  start,
};
