@echo off
echo Building kdbx-wasm...

cd /d "%~dp0\.."

set OUT_DIR=packages\kdbx-wasm
if defined CARGO_TARGET_DIR (
    set TARGET_DIR=%CARGO_TARGET_DIR%
) else (
    set TARGET_DIR=target
)
set WASM=%TARGET_DIR%\wasm32-unknown-unknown\release\kdbx_wasm.wasm

REM Build WASM target
cargo build --manifest-path crates\kdbx-wasm\Cargo.toml ^
  --lib --target wasm32-unknown-unknown --release

REM Generate Web bindings
wasm-bindgen %WASM% ^
  --out-dir %OUT_DIR%\web ^
  --target web ^
  --no-typescript

REM Generate Node.js bindings
wasm-bindgen %WASM% ^
  --out-dir %OUT_DIR%\nodejs ^
  --target nodejs ^
  --no-typescript

REM Generate Bundler bindings (default fallback for Vite/Webpack/etc.)
wasm-bindgen %WASM% ^
  --out-dir %OUT_DIR% ^
  --target bundler ^
  --no-typescript

REM Run wasm-opt if available
where wasm-opt >nul 2>nul
if %ERRORLEVEL% == 0 (
    echo Running wasm-opt...
    wasm-opt -O3 %OUT_DIR%\web\kdbx_wasm_bg.wasm -o %OUT_DIR%\web\kdbx_wasm_bg.wasm
    wasm-opt -O3 %OUT_DIR%\nodejs\kdbx_wasm_bg.wasm -o %OUT_DIR%\nodejs\kdbx_wasm_bg.wasm
    wasm-opt -O3 %OUT_DIR%\kdbx_wasm_bg.wasm -o %OUT_DIR%\kdbx_wasm_bg.wasm
) else (
    echo wasm-opt not found, skipping (install via: https://github.com/WebAssembly/binaryen)
)

echo Build complete.
echo   Web:    %OUT_DIR%\web\
echo   Nodejs: %OUT_DIR%\nodejs\
echo   Bundler: %OUT_DIR%\kdbx_wasm.js
