#!/usr/bin/env bash
set -e

echo "Building kdbx-wasm..."

cd "$(dirname "$0")/.."

# Fail fast if the wasm32 target is missing (otherwise cargo fails mid-build)
if command -v rustup &> /dev/null; then
    if ! rustup target list --installed 2>/dev/null | grep -qx 'wasm32-unknown-unknown'; then
        echo "ERROR: rust target wasm32-unknown-unknown is not installed." >&2
        echo "       Fix: rustup target add wasm32-unknown-unknown" >&2
        exit 1
    fi
fi

# Build WASM target
cargo build --manifest-path crates/kdbx-wasm/Cargo.toml \
  --lib --target wasm32-unknown-unknown --release

OUT_DIR="packages/kdbx-wasm"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
WASM="$TARGET_DIR/wasm32-unknown-unknown/release/kdbx_wasm.wasm"

# Generate the single ESM binding (fetch-based async init for browsers and
# bundlers). The Node.js entry, index.js, reuses its initSync export with
# fs.readFileSync, so both runtimes share this one glue file and one .wasm.
wasm-bindgen "$WASM" \
  --out-dir "$OUT_DIR" \
  --target web \
  --no-typescript

# Clean up outputs from the previous multi-target layout
rm -f "$OUT_DIR/kdbx_wasm_bg.js"
rm -rf "$OUT_DIR/web" "$OUT_DIR/nodejs"

# Run wasm-opt if available
if command -v wasm-opt &> /dev/null; then
    echo "Running wasm-opt..."
    wasm-opt -O3 "$OUT_DIR/kdbx_wasm_bg.wasm" -o "$OUT_DIR/kdbx_wasm_bg.wasm"
else
    echo "wasm-opt not found, skipping (install via: https://github.com/WebAssembly/binaryen)"
fi

echo "Build complete."
echo "  ESM binding: $OUT_DIR/kdbx_wasm.js"
echo "  Node entry:  $OUT_DIR/index.js"
