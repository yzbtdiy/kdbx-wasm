# kdbx-wasm

A high-performance KDBX 4 password database parser built with Rust and WebAssembly. Works in both **browsers** and **Node.js**.

[![npm version](https://img.shields.io/npm/v/kdbx-wasm.svg)](https://www.npmjs.com/package/kdbx-wasm)
[![license](https://img.shields.io/npm/l/kdbx-wasm.svg)](https://github.com/yzbtdiy/kdbx-wasm/blob/master/LICENSE)

## Features

- **KDBX 4 format** — parse, modify, and generate `.kdbx` files
- **Encryption** — AES-256-CBC and ChaCha20
- **Key derivation** — Argon2d, Argon2id, and AES-KDF
- **WebAssembly** — Rust-powered, runs in browsers and Node.js
- **TypeScript** — full type definitions included
- **Secure** — sensitive data auto-zeroed from memory

## Installation

```bash
npm install kdbx-wasm
```

## Usage — Browser

> WASM must be initialized before use. Call `init()` (from `kdbx_wasm.js`) once at startup.

```html
<!DOCTYPE html>
<html>
<body>
  <input type="file" id="file" accept=".kdbx" />
  <input type="password" id="password" placeholder="Master password" />
  <button id="open">Open</button>
  <pre id="output"></pre>

  <script type="module">
    import init, { KdbxDatabase, isKdbxFile, getFileInfo } from 'kdbx-wasm/kdbx_wasm.js';

    // Initialize WASM module
    await init();

    document.getElementById('open').addEventListener('click', async () => {
      const file = document.getElementById('file').files[0];
      if (!file) return;

      const data = new Uint8Array(await file.arrayBuffer());
      const password = document.getElementById('password').value;

      // Quick check without decryption
      if (!isKdbxFile(data)) {
        document.getElementById('output').textContent = 'Not a valid KDBX file';
        return;
      }

      // Inspect file metadata (no password required)
      const info = getFileInfo(data);
      console.log('Encryption:', info.encryptionAlgorithm); // 'AES-256' | 'ChaCha20'
      console.log('KDF:', info.kdfAlgorithm);               // 'Argon2d' | 'Argon2id' | 'AES-KDF'

      // Open database
      const db = new KdbxDatabase(data, password);

      // Metadata & header
      console.log('Database name:', db.metadata.databaseName);
      console.log('Entries:', db.headerInfo.entryCount);

      // List all groups
      const groups = db.getGroups();
      groups.forEach(g => console.log(`Group: ${g.name} (${g.uuid})`));

      // List all entries
      const entries = db.getEntries();
      entries.forEach(entry => {
        console.log(`${entry.title} — ${entry.username}`);
      });

      // Search
      const results = db.searchEntries('github');
      console.log('Search results:', results.length);

      // Get entries in a specific group
      const rootEntries = db.getEntriesByGroup(db.rootGroupUuid);

      // Export back to .kdbx bytes
      const exported = db.toBytes(password);
      // Download as file:
      // const blob = new Blob([exported], { type: 'application/octet-stream' });
      // window.open(URL.createObjectURL(blob));

      // Display results
      document.getElementById('output').textContent = JSON.stringify(entries, null, 2);
    });
  </script>
</body>
</html>
```

## Usage — Node.js

> Node.js >= 16 required. Uses the `node` target WASM build.

```js
import { readFileSync, writeFileSync } from 'node:fs';
import { KdbxDatabase, isKdbxFile, getFileInfo } from 'kdbx-wasm';

// Load KDBX file
const fileData = new Uint8Array(readFileSync('passwords.kdbx'));

// ── Quick check ──────────────────────────────────────
console.log('Valid KDBX:', isKdbxFile(fileData)); // true

// ── File info (no password needed) ───────────────────
const info = getFileInfo(fileData);
console.log('Version:', info.version);             // '4.0'
console.log('Encryption:', info.encryptionAlgorithm); // 'AES-256'
console.log('KDF:', info.kdfAlgorithm);            // 'Argon2id'
console.log('Compression:', info.compression);     // 'Gzip'

// ── Open database ────────────────────────────────────
const db = new KdbxDatabase(fileData, 'master-password');
//   with key file:
//   const keyFile = new Uint8Array(readFileSync('secret.key'));
//   const db = new KdbxDatabase(fileData, 'password', keyFile);

// ── Metadata ─────────────────────────────────────────
console.log('Database:', db.metadata.databaseName);
console.log('Entries:', db.headerInfo.entryCount);
console.log('Groups:', db.headerInfo.groupCount);

// ── List groups ──────────────────────────────────────
const groups = db.getGroups();
for (const group of groups) {
  console.log(`📁 ${group.name} (${group.entries.length} entries)`);
}

// ── List all entries ─────────────────────────────────
const entries = db.getEntries();
for (const entry of entries) {
  console.log(`  ${entry.title}`);
  console.log(`    User: ${entry.username}`);
  console.log(`    URL:  ${entry.url ?? '-'}`);
  // entry.password is available but omitted here for safety
}

// ── Get single entry ─────────────────────────────────
const entry = db.getEntry(entries[0].uuid);
console.log('Password:', entry.password);

// ── Search ───────────────────────────────────────────
const results = db.searchEntries('google');
console.log(`Found ${results.length} entries matching "google"`);

// ── Group entries ────────────────────────────────────
const rootEntries = db.getEntriesByGroup(db.rootGroupUuid);
console.log(`Root group has ${rootEntries.length} entries`);

// ── Export ────────────────────────────────────────────
const exported = db.toBytes('new-password');
writeFileSync('exported.kdbx', exported);
console.log('Saved exported.kdbx');
```

## API Reference

### `KdbxDatabase`

```typescript
new KdbxDatabase(data: Uint8Array, password?: string, keyFile?: Uint8Array)
```

| Property | Type | Description |
|----------|------|-------------|
| `metadata` | `KdbxMetadata` | Database name, description, default username |
| `headerInfo` | `KdbxHeaderInfo` | Encryption algorithm, KDF, entry/group counts |
| `rootGroupUuid` | `string` | UUID of the root group |

| Method | Returns | Description |
|--------|---------|-------------|
| `getEntries()` | `KdbxEntry[]` | All entries |
| `getEntry(uuid)` | `KdbxEntry` | Single entry by UUID |
| `getGroups()` | `KdbxGroup[]` | All groups |
| `getGroup(uuid)` | `KdbxGroup` | Single group by UUID |
| `getEntriesByGroup(groupUuid)` | `KdbxEntry[]` | Entries in a group |
| `searchEntries(query)` | `KdbxEntry[]` | Search by keyword (title, username, URL, notes) |
| `toBytes(password?, keyFile?)` | `Uint8Array` | Export as KDBX bytes |

### Utility Functions

```typescript
isKdbxFile(data: Uint8Array): boolean     // Check KDBX signature
getFileInfo(data: Uint8Array): KdbxFileInfo // Header info without decryption
```

### Types

```typescript
interface KdbxEntry {
  uuid: string;
  groupId: string;
  title: string;
  username?: string;
  password: string;
  url?: string;
  notes?: string;
  iconId: number;
  createdAt: string;
  updatedAt: string;
  accessedAt: string;
  expiresAt?: string;
  tags: string[];
  customFields: Record<string, string>;
}

interface KdbxGroup {
  uuid: string;
  name: string;
  iconId: number;
  parentId?: string;
  createdAt: string;
  updatedAt: string;
  notes?: string;
  childGroups: string[];
  entries: string[];
}

interface KdbxMetadata {
  databaseName?: string;
  databaseDescription?: string;
  defaultUsername?: string;
  maintenanceHistoryDays: number;
  color?: string;
}

interface KdbxHeaderInfo {
  version: string;
  encryptionAlgorithm: 'AES-256' | 'ChaCha20';
  kdfAlgorithm: 'Argon2d' | 'Argon2id' | 'AES-KDF';
  kdfParams: { memory?: number; iterations?: number; parallelism?: number; rounds?: number };
  compression: 'None' | 'Gzip';
  entryCount: number;
  groupCount: number;
}
```

## Building from Source

```bash
# Prerequisites: Rust 1.94+, wasm-bindgen-cli
cargo install wasm-bindgen-cli

# Build WASM module
.\build-wasm.bat

# Or manually:
cargo build --lib --target wasm32-unknown-unknown --release
wasm-bindgen target/wasm32-unknown-unknown/release/kdbx_wasm.wasm \
  --out-dir js --target web --no-typescript
```

## Browser Compatibility

Chrome 57+ · Firefox 52+ · Safari 11+ · Edge 16+

## Security

- Master password derives the encryption key via Argon2/AES-KDF
- Key file can be used alongside or instead of a password
- All cryptographic operations execute inside WebAssembly
- Sensitive data is cleared from memory when possible

## License

MIT
