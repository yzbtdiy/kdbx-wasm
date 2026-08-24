@echo off
setlocal
echo Building kdbx-wasm...

cd /d "%~dp0\.."

REM Fail fast if the wasm32 target is missing (otherwise cargo fails mid-build)
REM Note: /c: substring match, not /x -- rustup emits LF-only lines that break findstr /x
rustup target list --installed 2>nul | findstr /c:"wasm32-unknown-unknown" >nul
if errorlevel 1 (
    echo ERROR: rust target wasm32-unknown-unknown is not installed. 1>&2
    echo        Fix: rustup target add wasm32-unknown-unknown 1>&2
    exit /b 1
)

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
if errorlevel 1 goto :fail

REM Generate the single ESM binding -- fetch-based async init for browsers and
REM bundlers. The Node.js entry, index.js, reuses its initSync export with
REM fs.readFileSync, so both runtimes share this one glue file and one .wasm.
wasm-bindgen %WASM% ^
  --out-dir %OUT_DIR% ^
  --target web ^
  --no-typescript
if errorlevel 1 goto :fail

REM Clean up outputs from the previous multi-target layout
if exist %OUT_DIR%\kdbx_wasm_bg.js del /q %OUT_DIR%\kdbx_wasm_bg.js
if exist %OUT_DIR%\web rmdir /s /q %OUT_DIR%\web
if exist %OUT_DIR%\nodejs rmdir /s /q %OUT_DIR%\nodejs

REM Run wasm-opt if available
REM Note: no parentheses in echo text inside if-blocks -- cmd treats ")" as block end
where wasm-opt >nul 2>nul
if errorlevel 1 (
    echo wasm-opt not found, skipping. Install via https://github.com/WebAssembly/binaryen
    goto :done
)

echo Running wasm-opt...
wasm-opt -O3 %OUT_DIR%\kdbx_wasm_bg.wasm -o %OUT_DIR%\kdbx_wasm_bg.wasm
if errorlevel 1 goto :fail

:done
echo Build complete.
echo   ESM binding: %OUT_DIR%\kdbx_wasm.js
echo   Node entry:  %OUT_DIR%\index.js
exit /b 0

:fail
echo.
echo Build FAILED, aborting. 1>&2
exit /b 1
