#!/usr/bin/env bash
set -e

echo "Building kdbx-wasm..."

cd "$(dirname "$0")/.."

# Build WASM target
cargo build --manifest-path crates/kdbx-wasm/Cargo.toml \
  --lib --target wasm32-unknown-unknown --release

OUT_DIR="packages/kdbx-wasm"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
WASM="$TARGET_DIR/wasm32-unknown-unknown/release/kdbx_wasm.wasm"

# Generate Web bindings
wasm-bindgen "$WASM" \
  --out-dir "$OUT_DIR/web" \
  --target web \
  --no-typescript

# Generate Node.js bindings
wasm-bindgen "$WASM" \
  --out-dir "$OUT_DIR/nodejs" \
  --target nodejs \
  --no-typescript

# Generate Bundler bindings (default fallback for Vite/Webpack/etc.)
wasm-bindgen "$WASM" \
  --out-dir "$OUT_DIR" \
  --target bundler \
  --no-typescript

# Run wasm-opt if available for all targets
WASM_OPT="wasm-opt"
if command -v "$WASM_OPT" &> /dev/null; then
    echo "Running wasm-opt..."
    for target in web nodejs "$OUT_DIR"; do
        WASM_FILE="$target/kdbx_wasm_bg.wasm"
        if [ -f "$WASM_FILE" ]; then
            $WASM_OPT -O3 "$WASM_FILE" -o "$WASM_FILE"
        fi
    done
else
    echo "wasm-opt not found, skipping (install via: https://github.com/WebAssembly/binaryen)"
fi

echo "Build complete."
echo "  Web:    $OUT_DIR/web/"
echo "  Nodejs: $OUT_DIR/nodejs/"
echo "  Bundler: $OUT_DIR/kdbx_wasm.js"
