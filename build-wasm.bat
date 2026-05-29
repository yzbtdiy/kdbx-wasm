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

REM Resolve target directory (respect CARGO_TARGET_DIR)
if defined CARGO_TARGET_DIR (
    set "TARGET_DIR=%CARGO_TARGET_DIR%"
) else (
    set "TARGET_DIR=target"
)

wasm-bindgen "%TARGET_DIR%\wasm32-unknown-unknown\release\kdbx_wasm.wasm" ^
    --out-dir js ^
    --target web ^
    --no-typescript

REM Optional: optimize WASM size with wasm-opt
where wasm-opt >nul 2>nul
if %errorlevel% equ 0 (
    echo Optimizing WASM with wasm-opt...
    wasm-opt js\kdbx_wasm_bg.wasm -O3 -o js\kdbx_wasm_bg.wasm
) else (
    echo wasm-opt not found, skipping optimization. Install binaryen for smaller WASM files.
)

echo Build complete! Output in js/
