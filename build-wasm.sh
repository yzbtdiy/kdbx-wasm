#!/usr/bin/env bash
set -e

echo "Building WASM module..."

cargo build --lib --target wasm32-unknown-unknown --release

if ! command -v wasm-bindgen &> /dev/null; then
    echo "wasm-bindgen not found. Installing..."
    cargo install wasm-bindgen-cli
fi

# Resolve target directory (respect CARGO_TARGET_DIR)
if [ -n "$CARGO_TARGET_DIR" ]; then
    TARGET_DIR="$CARGO_TARGET_DIR"
else
    TARGET_DIR="target"
fi

wasm-bindgen "$TARGET_DIR/wasm32-unknown-unknown/release/kdbx_wasm.wasm" \
    --out-dir js \
    --target web \
    --no-typescript

# Optional: optimize WASM size with wasm-opt
if command -v wasm-opt &> /dev/null; then
    echo "Optimizing WASM with wasm-opt..."
    wasm-opt js/kdbx_wasm_bg.wasm -O3 -o js/kdbx_wasm_bg.wasm
else
    echo "wasm-opt not found, skipping optimization. Install binaryen for smaller WASM files."
fi

echo "Build complete! Output in js/"
