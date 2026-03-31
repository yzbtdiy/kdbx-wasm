@echo off
REM Build script for KDBX WASM module

echo Building WASM module...

cargo build --lib --target wasm32-unknown-unknown --release
if %errorlevel% neq 0 (
    echo Build failed!
    exit /b 1
)

where wasm-bindgen >nul 2>nul
if %errorlevel% neq 0 (
    echo wasm-bindgen not found. Installing...
    cargo install wasm-bindgen-cli
)

wasm-bindgen target\wasm32-unknown-unknown\release\kdbx_wasm.wasm ^
    --out-dir js ^
    --target web ^
    --no-typescript

echo Build complete! Output in js/
