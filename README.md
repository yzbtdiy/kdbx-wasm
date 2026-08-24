# kdbx-wasm

A high-performance **KDBX 4** password database parser built with **Rust** and **WebAssembly**.

[![npm version](https://img.shields.io/npm/v/kdbx-wasm.svg)](https://www.npmjs.com/package/kdbx-wasm)
[![license](https://img.shields.io/npm/l/kdbx-wasm.svg)](https://github.com/yzbtdiy/kdbx-wasm/blob/master/LICENSE)

## Features

- **KDBX 4** — parse, modify, and export `.kdbx` files
- **Encryption** — AES-256-CBC / ChaCha20
- **Key derivation** — Argon2d / Argon2id / AES-KDF
- **WebAssembly** — Rust-powered, runs in browsers and Node.js
- **TypeScript** — full type definitions included
- **Zero dependencies** — standalone, no native addons

## Supported KeePass Features

| Feature | Status |
|---|---|
| AES-256 / ChaCha20 encryption | ✅ |
| Argon2d / Argon2id / AES-KDF | ✅ |
| Gzip compression | ✅ |
| Groups & Entries | ✅ |
| Custom Fields | ✅ (plain Object) |
| Entry History | ✅ (round-trip preserved) |
| Binary Attachments | ✅ (round-trip preserved, incl. references) |
| Tags | ✅ |
| Password + Key File | ✅ (raw, XML v1/v2, hex) |

> **Note**: KDBX 3.x is **not supported**. Only KDBX 4 files can be opened.

---

## Installation

```bash
npm install kdbx-wasm
```

### Prerequisites for Node.js

Node.js **19+** (ESM only; uses the global `crypto` module for random number generation).

> **Note**: On Node 18, `toBytes()` and `createEntry()` require a `globalThis.crypto` polyfill (e.g. `import { webcrypto } from 'node:crypto'; globalThis.crypto ??= webcrypto;`).

---

## Quick Start — Node.js

The WASM module loads synchronously on import — no init call needed.

```js
import { readFileSync, writeFileSync } from 'node:fs';
import { KdbxDatabase, isKdbxFile, getFileInfo } from 'kdbx-wasm';

// 1. Read the file
const data = new Uint8Array(readFileSync('passwords.kdbx'));

// 2. Quick validation
if (!isKdbxFile(data)) {
    throw new Error('Not a valid KDBX file');
}

// 3. Peek header info without decrypting
const info = getFileInfo(data);
console.log('Encryption:', info.encryptionAlgorithm);  // "AES-256"
console.log('KDF:', info.kdfAlgorithm);                // "Argon2id"
console.log('Compression:', info.compression);          // "Gzip"

// 4. Open the database
const db = new KdbxDatabase(data, 'master-password');
// With key file:
// const db = new KdbxDatabase(data, 'password', keyFileBytes);

// 5. Read metadata
console.log('Database name:', db.metadata.databaseName);
console.log('Entries:', db.headerInfo.entryCount);
console.log('Groups:', db.headerInfo.groupCount);

// 6. List all entries (passwords excluded by default)
for (const entry of db.getEntries()) {
    console.log(entry.title, '-', entry.username);
}

// 7. List all groups
for (const group of db.getGroups()) {
    console.log(group.name, `(${group.entries.length} entries)`);
}

// 8. Export to a new file
writeFileSync('exported.kdbx', db.toBytes('new-password'));
```

---

## Quick Start — Browser

In browsers the WASM module loads asynchronously — call the default export's `init()` once before first use:

```html
<script type="module">
  import init, { KdbxDatabase, isKdbxFile, getFileInfo } from 'kdbx-wasm';
  await init();

  const input = document.getElementById('fileInput');
  input.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    const data = new Uint8Array(await file.arrayBuffer());

    if (!isKdbxFile(data)) {
      alert('Not a KDBX file');
      return;
    }

    const db = new KdbxDatabase(data, 'master-password');
    const entries = db.getEntries();

    for (const entry of entries) {
      console.log(entry.title, entry.username);
    }
  });
</script>
```

> **How the entry is picked**: the package `exports` field routes `import 'kdbx-wasm'` to a synchronous Node.js loader on Node (no init needed) and to the fetch-based browser/bundler module everywhere else.

---

## Working with Entries

### Read entries

```js
const db = new KdbxDatabase(data, 'password');

// Get all entries (passwords hidden by default)
const entries = db.getEntries();

// Include passwords
const entriesWithPw = db.getEntries(true);

// Get a single entry by UUID
const entry = db.getEntry('550e8400-e29b-41d4-a716-446655440000', true);
console.log(entry.title);      // "GitHub"
console.log(entry.username);   // "myuser"
console.log(entry.password);   // "secret123"
console.log(entry.url);        // "https://github.com"
console.log(entry.notes);      // "2FA enabled"
console.log(entry.tags);       // ["work", "dev"]

// Custom fields are plain Objects (not Map)
console.log(entry.customFields);
// { "otp": "otpauth://...", "env": "production" }
console.log(Object.keys(entry.customFields));  // ["otp", "env"]
```

### Search entries

```js
// Simple full-text search (searches title, username, URL, notes, tags, custom field VALUES)
const results = db.searchEntries('github');

// Include passwords in search results
const resultsWithPw = db.searchEntries('github', true);

// Advanced search with filters
const advanced = db.searchEntriesAdvanced(
    'github',           // text query (optional)
    groupUuid,          // limit to a specific group (optional)
    true,               // exclude expired entries (optional)
    false               // include passwords (optional)
);
```

### Get entries by group

```js
const rootUuid = db.rootGroupUuid;
const rootEntries = db.getEntriesByGroup(rootUuid);

// Or find a group by name
const groups = db.getGroups();
const workGroup = groups.find(g => g.name === 'Work');
const workEntries = db.getEntriesByGroup(workGroup.uuid, true);
```

### Create, modify, and delete entries

```js
// Create a new entry
const newUuid = db.createEntry(groupUuid, 'New Service', 'generated-password');

// Modify fields
 db.setEntryTitle(newUuid, 'Updated Title');
 db.setEntryUsername(newUuid, 'newuser');
 db.setEntryPassword(newUuid, 'newpassword');
 db.setEntryUrl(newUuid, 'https://example.com');
 db.setEntryNotes(newUuid, 'Some notes');
 db.setEntryIconId(newUuid, 1);

// Custom fields
db.setEntryCustomField(newUuid, 'OTP', '123456');
db.setEntryCustomField(newUuid, 'Environment', 'production');
// To remove a custom field, pass undefined:
db.setEntryCustomField(newUuid, 'OTP', undefined);

// Tags
db.addEntryTag(newUuid, 'work');
db.removeEntryTag(newUuid, 'personal');

// Set expiry date (RFC 3339)
db.setEntryExpires(newUuid, '2026-12-31T23:59:59Z');
// Clear expiry:
db.setEntryExpires(newUuid, undefined);

// Move to another group
db.moveEntry(newUuid, anotherGroupUuid);

// Delete
db.deleteEntry(newUuid);
```

---

## Working with Groups

```js
// List all groups
const groups = db.getGroups();
for (const g of groups) {
    console.log(g.name, 'parent:', g.parentId || 'root');
    console.log('  child groups:', g.childGroups.length);
    console.log('  entries:', g.entries.length);
}

// Get child groups
const children = db.getChildGroups(db.rootGroupUuid);

// Create a new group
const newGroupId = db.createGroup('New Group', parentGroupUuid);
// Create a root group (omit parent):
// const rootId = db.createGroup('Root');

// Rename
db.renameGroup(newGroupId, 'Renamed Group');

// Set notes
db.setGroupNotes(newGroupId, 'Group description');

// Update icon
db.setGroupIconId(newGroupId, 42);

// Delete (only works if empty)
db.deleteGroup(newGroupId);
```

---

## Working with Metadata

```js
// Read
console.log(db.metadata.databaseName);           // "My Passwords"
console.log(db.metadata.databaseDescription);    // "Personal vault"
console.log(db.metadata.defaultUsername);        // "myuser"
console.log(db.metadata.maintenanceHistoryDays); // 365
console.log(db.metadata.color);                  // "#FF0000"

// Modify
db.setDatabaseName('New Name');
db.setDatabaseDescription('Updated description');
db.setDefaultUsername('defaultuser');
// To clear a field, pass undefined:
db.setDatabaseName(undefined);
```

---

## Export (Round-trip)

```js
// Export with the same password
const samePassword = db.toBytes('master-password');

// Export with a new password
const newPassword = db.toBytes('new-password');

// Export with a key file
const withKeyFile = db.toBytes('password', keyFileBytes);

// Verify round-trip
const db2 = new KdbxDatabase(samePassword, 'master-password');
console.log(db2.headerInfo.entryCount === db.headerInfo.entryCount);  // true
```

> **Note**: The exported file may be slightly smaller than the original. This is normal — some KeePass-specific internal data (e.g., unused custom icons, template groups) is not fully preserved. All entries, groups, custom fields, history, and binary attachments are retained.

---

## API Reference

### `KdbxDatabase`

```ts
new KdbxDatabase(data: Uint8Array, password?: string, keyFile?: Uint8Array)
```

| Property | Type | Description |
|---|---|---|
| `metadata` | `KdbxMetadata` | Database name, description, default username, maintenance history days, color |
| `headerInfo` | `KdbxHeaderInfo` | Encryption algorithm, KDF params, entry/group counts |
| `rootGroupUuid` | `string` | UUID of the root group |

#### Query Methods

| Method | Returns | Description |
|---|---|---|
| `getEntries(includePassword?)` | `KdbxEntry[]` | All entries. Passwords excluded by default. |
| `getEntry(uuid, includePassword?)` | `KdbxEntry` | Single entry by UUID |
| `getGroups()` | `KdbxGroup[]` | All groups |
| `getGroup(uuid)` | `KdbxGroup` | Single group by UUID |
| `getEntriesByGroup(uuid, includePassword?)` | `KdbxEntry[]` | Entries in a specific group |
| `getChildGroups(uuid)` | `KdbxGroup[]` | Direct child groups |
| `searchEntries(query, includePassword?)` | `KdbxEntry[]` | Full-text search across title, username, URL, notes, tags, and **custom field values** |
| `searchEntriesAdvanced(query?, groupUuid?, excludeExpired?, includePassword?)` | `KdbxEntry[]` | Advanced search with optional filters |

#### Entry Mutations

| Method | Description |
|---|---|
| `createEntry(groupUuid, title, password)` | Create a new entry, returns entry UUID |
| `deleteEntry(uuid)` | Delete an entry |
| `moveEntry(entryUuid, targetGroupUuid)` | Move entry to another group |
| `setEntryTitle(uuid, title)` | Update title |
| `setEntryUsername(uuid, username?)` | Update or clear username |
| `setEntryPassword(uuid, password)` | Update password |
| `setEntryUrl(uuid, url?)` | Update or clear URL |
| `setEntryNotes(uuid, notes?)` | Update or clear notes |
| `setEntryIconId(uuid, iconId)` | Update icon ID |
| `addEntryTag(uuid, tag)` | Add a tag |
| `removeEntryTag(uuid, tag)` | Remove a tag |
| `setEntryCustomField(uuid, key, value?)` | Set or remove a custom field |
| `setEntryExpires(uuid, expiresAt?)` | Set or clear expiry date (RFC 3339) |

#### Group Mutations

| Method | Description |
|---|---|
| `createGroup(name, parentUuid?)` | Create a group. Omit `parentUuid` to create root. |
| `deleteGroup(uuid)` | Delete a group (must be empty) |
| `renameGroup(uuid, name)` | Rename a group |
| `setGroupNotes(uuid, notes?)` | Set or clear group notes |
| `setGroupIconId(uuid, iconId)` | Update group icon |

#### Metadata Mutations

| Method | Description |
|---|---|
| `setDatabaseName(name?)` | Set or clear database name |
| `setDatabaseDescription(description?)` | Set or clear description |
| `setDefaultUsername(username?)` | Set or clear default username |

#### Export

| Method | Returns | Description |
|---|---|---|
| `toBytes(password?, keyFile?)` | `Uint8Array` | Export as `.kdbx` bytes |

### Utility Functions

```ts
isKdbxFile(data: Uint8Array): boolean
getFileInfo(data: Uint8Array): KdbxFileInfo
```

### Types

```ts
interface KdbxEntry {
  uuid: string;
  iconId: number;
  groupId: string;
  title: string;
  username?: string;
  password?: string;   // only present when explicitly requested
  url?: string;
  notes?: string;
  createdAt: string;   // RFC 3339
  updatedAt: string;
  accessedAt: string;
  expiresAt?: string;
  tags: string[];
  customFields: Record<string, string>;  // plain Object, NOT Map
}

interface KdbxGroup {
  uuid: string;
  name: string;
  iconId: number;
  parentId?: string;
  createdAt: string;
  updatedAt: string;
  notes?: string;
  childGroups: string[];  // UUID array
  entries: string[];      // UUID array
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
  kdfParams: {
    memory?: number;
    iterations?: number;
    parallelism?: number;
    rounds?: number;
  };
  compression: 'None' | 'Gzip';
  entryCount: number;
  groupCount: number;
}
```

---

## Building from Source

```bash
# Prerequisites
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli

# Build WASM
./scripts/build-wasm.sh        # Unix (Git Bash, WSL, macOS, Linux)
.\scripts\build-wasm.bat       # Windows (cmd, PowerShell)
```

This generates:
- `packages/kdbx-wasm/kdbx_wasm.js` — single ESM binding (browser/bundler entry, fetch-based `init()`)
- `packages/kdbx-wasm/kdbx_wasm_bg.wasm` — the WASM binary (one copy, shared by all entries)
- `packages/kdbx-wasm/index.js` — Node.js ESM entry (loads the WASM synchronously via `initSync` + `fs.readFileSync`; hand-written, not generated)

---

## Browser Compatibility

Chrome 57+ · Firefox 52+ · Safari 11+ · Edge 16+

Requires WebAssembly support and ESM (`import`).

---

## Security Notes

- **Passwords are never included by default**. You must explicitly pass `includePassword: true` to `getEntries()` or `getEntry()`.
- When passwords are returned, they are **plain text strings** in JavaScript memory. They are **not** automatically cleared. Handle them carefully.
- All cryptographic operations (AES, ChaCha20, Argon2, HMAC) run inside the WebAssembly sandbox.
- `SecString` / `SecVec` types in Rust use `zeroize` to clear memory on drop, but this does not extend to JavaScript's string heap.

---

## License

MIT
