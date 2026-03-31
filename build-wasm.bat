@echo off
REM Build script for KDBX WASM module

echo Building WASM module...

REM Build for web target
cargo build --target wasm32-unknown-unknown --release

if %errorlevel% neq 0 (
    echo Build failed!
    exit /b 1
)

REM Check if wasm-bindgen is installed
where wasm-bindgen >nul 2>nul
if %errorlevel% neq 0 (
    echo wasm-bindgen not found. Installing...
    cargo install wasm-bindgen-cli
)

REM Generate JS bindings
wasm-bindgen target\wasm32-unknown-unknown\release\kdbx_rs.wasm \
    --out-dir js \
    --target web \
    --no-typescript

echo Build complete!
echo Output files are in the js/ directory
