# kdbx-wasm

A high-performance KDBX 4 password database parser built with Rust and WebAssembly.

[![npm version](https://img.shields.io/npm/v/kdbx-wasm.svg)](https://www.npmjs.com/package/kdbx-wasm)
[![license](https://img.shields.io/npm/l/kdbx-wasm.svg)](https://github.com/yzbtdiy/kdbx-wasm/blob/master/LICENSE)

## Features

- **KDBX 4** — parse, modify, and export `.kdbx` files
- **Encryption** — AES-256-CBC / ChaCha20
- **Key derivation** — Argon2d / Argon2id / AES-KDF
- **WebAssembly** — Rust-powered, runs in browsers and Node.js
- **TypeScript** — full type definitions included

## Project Structure

```
.
├── Cargo.toml              # Rust workspace root
├── crates/
│   ├── kdbx-core/          # Core Rust library (KDBX parser)
│   └── kdbx-wasm/          # wasm-bindgen bindings (WASM target)
├── packages/
│   └── kdbx-wasm/          # npm package (wrapper + WASM binary)
└── scripts/
    ├── build-wasm.sh       # Build script (Unix)
    └── build-wasm.bat      # Build script (Windows)
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
| `getEntries(includePassword?)` | `KdbxEntry[]` | All entries |
| `getEntry(uuid, includePassword?)` | `KdbxEntry` | Single entry by UUID |
| `getGroups()` | `KdbxGroup[]` | All groups |
| `getGroup(uuid)` | `KdbxGroup` | Single group by UUID |
| `getEntriesByGroup(uuid, includePassword?)` | `KdbxEntry[]` | Entries in a group |
| `getChildGroups(uuid)` | `KdbxGroup[]` | Child groups of a group |
| `searchEntries(query, includePassword?)` | `KdbxEntry[]` | Full-text search (title, username, URL, notes, tags, custom fields) |
| `searchEntriesAdvanced(query?, groupUuid?, excludeExpired?, includePassword?)` | `KdbxEntry[]` | Advanced search with filters |
| `toBytes(password?, keyFile?)` | `Uint8Array` | Export as `.kdbx` bytes |

**Entry mutations:** `createEntry`, `deleteEntry`, `moveEntry`, `setEntryTitle`, `setEntryUsername`, `setEntryPassword`, `setEntryUrl`, `setEntryNotes`, `setEntryIconId`, `addEntryTag`, `removeEntryTag`, `setEntryCustomField`, `setEntryExpires`

**Group mutations:** `createGroup`, `deleteGroup`, `renameGroup`, `setGroupNotes`, `setGroupIconId`

**Metadata mutations:** `setDatabaseName`, `setDatabaseDescription`, `setDefaultUsername`

### Utility Functions

```ts
isKdbxFile(data: Uint8Array): boolean
getFileInfo(data: Uint8Array): KdbxFileInfo
```

### Types

```ts
interface KdbxEntry {
  uuid: string; groupId: string; title: string;
  username?: string; password?: string; url?: string; notes?: string;
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
./scripts/build-wasm.sh        # Unix
.\scripts\build-wasm.bat       # Windows
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
