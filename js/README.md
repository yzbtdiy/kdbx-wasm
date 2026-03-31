# kdbx-wasm

A high-performance KDBX 4 password database parser built with Rust and WebAssembly.

[![npm version](https://img.shields.io/npm/v/kdbx-wasm.svg)](https://www.npmjs.com/package/kdbx-wasm)
[![license](https://img.shields.io/npm/l/kdbx-wasm.svg)](https://github.com/yzbtdiy/kdbx-wasm/blob/master/LICENSE)

## Features

- **KDBX 4** — parse, modify, and export `.kdbx` files
- **Encryption** — AES-256-CBC / ChaCha20
- **Key derivation** — Argon2d / Argon2id / AES-KDF
- **WebAssembly** — Rust-powered, runs in browsers and Node.js
- **REST API** — Axum-based HTTP server for non-WASM usage
- **TypeScript** — full type definitions included

## Project Structure

```
src/
├── core/           # KDBX format internals
│   ├── types.rs    #   data types (Entry, Group, Header …)
│   ├── crypto.rs   #   AES / ChaCha20 / Argon2 / HMAC
│   ├── header.rs   #   binary header parsing
│   ├── xml.rs      #   XML payload ↔ entries/groups
│   └── parser.rs   #   parse & generate full .kdbx files
├── service/        # Business logic (session, file, entry, group)
├── api/            # Axum REST handlers + DTOs (server target)
├── infrastructure/ # Config loading
├── wasm.rs         # wasm-bindgen bindings (WASM target)
├── error.rs        # Unified error type
├── lib.rs          # Library root
└── main.rs         # Server entry point
js/                 # npm package (wrapper + WASM binary)
```

## Installation

```bash
npm install kdbx-wasm
```

## Quick Start — Browser

```html
<script type="module">
  import init, { KdbxDatabase, isKdbxFile, getFileInfo } from 'kdbx-wasm/kdbx_wasm.js';
  await init();

  const resp = await fetch('passwords.kdbx');
  const data = new Uint8Array(await resp.arrayBuffer());

  if (!isKdbxFile(data)) throw new Error('Not a KDBX file');

  const info = getFileInfo(data);
  console.log(info.encryptionAlgorithm, info.kdfAlgorithm);

  const db = new KdbxDatabase(data, 'master-password');
  console.log('Name:', db.metadata.databaseName);

  const entries = db.getEntries();
  entries.forEach(e => console.log(e.title, e.username));

  const results = db.searchEntries('github');
  console.log('Found:', results.length);

  const exported = db.toBytes('new-password');
</script>
```

## Quick Start — Node.js

```js
import { readFileSync, writeFileSync } from 'node:fs';
import { KdbxDatabase, isKdbxFile, getFileInfo } from 'kdbx-wasm';

const data = new Uint8Array(readFileSync('passwords.kdbx'));

console.log('Valid:', isKdbxFile(data));
console.log('Info:', getFileInfo(data));

const db = new KdbxDatabase(data, 'master-password');
// with key file: new KdbxDatabase(data, 'password', keyFileBytes)

console.log(db.metadata.databaseName);
console.log(db.headerInfo.entryCount, 'entries');

for (const g of db.getGroups()) console.log(g.name);
for (const e of db.getEntries()) console.log(e.title, e.username);

const entry = db.getEntry(db.getEntries()[0].uuid);
const byGroup = db.getEntriesByGroup(db.rootGroupUuid);
const found = db.searchEntries('google');

writeFileSync('exported.kdbx', db.toBytes('new-password'));
```

## API

### `KdbxDatabase`

```ts
new KdbxDatabase(data: Uint8Array, password?: string, keyFile?: Uint8Array)
```

| Property | Type | Description |
|---|---|---|
| `metadata` | `KdbxMetadata` | Database name, description, default username |
| `headerInfo` | `KdbxHeaderInfo` | Encryption algorithm, KDF, entry/group counts |
| `rootGroupUuid` | `string` | UUID of the root group |

| Method | Returns | Description |
|---|---|---|
| `getEntries()` | `KdbxEntry[]` | All entries |
| `getEntry(uuid)` | `KdbxEntry` | Single entry by UUID |
| `getGroups()` | `KdbxGroup[]` | All groups |
| `getGroup(uuid)` | `KdbxGroup` | Single group by UUID |
| `getEntriesByGroup(uuid)` | `KdbxEntry[]` | Entries in a group |
| `searchEntries(query)` | `KdbxEntry[]` | Full-text search (title, username, URL, notes, tags) |
| `toBytes(password?, keyFile?)` | `Uint8Array` | Export as `.kdbx` bytes |

### Utility Functions

```ts
isKdbxFile(data: Uint8Array): boolean
getFileInfo(data: Uint8Array): KdbxFileInfo
```

### Types

```ts
interface KdbxEntry {
  uuid: string; groupId: string; title: string;
  username?: string; password: string; url?: string; notes?: string;
  iconId: number; createdAt: string; updatedAt: string; accessedAt: string;
  expiresAt?: string; tags: string[]; customFields: Record<string, string>;
}

interface KdbxGroup {
  uuid: string; name: string; iconId: number; parentId?: string;
  createdAt: string; updatedAt: string; notes?: string;
  childGroups: string[]; entries: string[];
}

interface KdbxMetadata {
  databaseName?: string; databaseDescription?: string;
  defaultUsername?: string; maintenanceHistoryDays: number; color?: string;
}

interface KdbxHeaderInfo {
  version: string;
  encryptionAlgorithm: 'AES-256' | 'ChaCha20';
  kdfAlgorithm: 'Argon2d' | 'Argon2id' | 'AES-KDF';
  kdfParams: { memory?: number; iterations?: number; parallelism?: number; rounds?: number };
  compression: 'None' | 'Gzip';
  entryCount: number; groupCount: number;
}

interface KdbxFileInfo {
  version: string;
  encryptionAlgorithm: 'AES-256' | 'ChaCha20';
  kdfAlgorithm: 'Argon2d' | 'Argon2id' | 'AES-KDF';
  compression: 'None' | 'Gzip';
}
```

## Building from Source

```bash
# Prerequisites: Rust, wasm-bindgen-cli
cargo install wasm-bindgen-cli

# Build WASM
.\build-wasm.bat

# Or manually:
cargo build --lib --target wasm32-unknown-unknown --release
wasm-bindgen target\wasm32-unknown-unknown\release\kdbx_wasm.wasm --out-dir js --target web --no-typescript
```

## Browser Compatibility

Chrome 57+ · Firefox 52+ · Safari 11+ · Edge 16+

## Security

- Key derivation via Argon2 / AES-KDF
- Key file supported alongside or instead of password
- All crypto runs inside WebAssembly
- Sensitive data cleared from memory when possible

## License

MIT
