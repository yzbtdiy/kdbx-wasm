# Changelog

## [0.1.5] - 2026-03-31

### Changed
- Major code refactoring: flattened module hierarchy
  - `core/crypto/` (5 files) → single `core/crypto.rs`
  - `core/types/` (4 files) → single `core/types.rs`
  - `core/parser/` (4 files) → `core/parser.rs` + `core/header.rs` + `core/xml.rs`
  - `api/dto/` (3 files) → single `api/dto.rs`
  - `api/routes.rs` + `api/state.rs` → merged into `api/mod.rs`
  - `infrastructure/config.rs` → merged into `infrastructure/mod.rs`
- `KdbxError` now implements `IntoResponse`, eliminating handler error mapping boilerplate
- Argon2d/Argon2id share internal implementation
- Unified `generate_random_bytes` into `core::crypto`
- Removed unused `api/middleware/` module
- Updated README with project structure and concise examples

## [0.1.1] - 2026-03-21

### Changed
- Updated all Rust dependencies to latest versions
  - serde: 1.0.228 → 1.0.219
  - serde_json: 1.0 → 1.0.140
  - uuid: 1.22.0 → 1.16.0
  - flate2: 1.1.9 → 1.1.0
  - thiserror: 2.0.18 → 2.0.12
  - anyhow: 1.0 → 1.0.97
  - chacha20: 0.10.0 → 0.9.1
  - sha2: 0.10.9 → 0.10.8
  - cipher: 0.4 → 0.4.4
  - base64: 0.22 → 0.22.1
  - chrono: 0.4 → 0.4.40
  - bytes: 1.5 → 1.10.1
  - rand: 0.9 → 0.9.0
  - tracing: 0.1.44 → 0.1.41
  - getrandom: 0.2 → 0.3.4
  - axum: 0.8.8 → 0.8.1
  - tokio: 1.50.0 → 1.44.0
  - tower: 0.5 → 0.5.2
  - tower-http: 0.6 → 0.6.2
  - tracing-subscriber: 0.3 → 0.3.19
  - config: 0.15.19 → 0.15.11
  - futures: 0.3 → 0.3.31

## [0.1.0] - 2026-03-20

### Added
- Initial release
- KDBX 4 file format support
- AES-256 and ChaCha20 encryption support
- Argon2d, Argon2id, and AES-KDF key derivation
- WebAssembly bindings for JavaScript/TypeScript
- TypeScript type definitions
- Browser and Node.js support
