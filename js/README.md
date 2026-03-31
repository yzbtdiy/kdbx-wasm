# kdbx-wasm

A WebAssembly-based KDBX password database parser for JavaScript/TypeScript.

## Features

- **Pure Rust Implementation**: Zero-dependency KDBX 4 parser written in Rust
- **WebAssembly Powered**: Fast and secure parsing in the browser
- **Full KDBX 4 Support**: Supports AES-256 and ChaCha20 encryption, Argon2d/Argon2id/AES-KDF key derivation
- **TypeScript Support**: Full type definitions included
- **Secure**: Sensitive data handling with secure memory containers

## Installation

```bash
npm install kdbx-wasm
```

Or use directly in the browser:

```html
<script type="module">
  import { KdbxDatabase, isKdbxFile } from './index.js';
</script>
```

## Usage

### Basic Example

```javascript
import { KdbxDatabase, isKdbxFile, getFileInfo } from 'kdbx-rs';

// Load a KDBX file
const response = await fetch('passwords.kdbx');
const fileData = new Uint8Array(await response.arrayBuffer());

// Check if it's a valid KDBX file
if (isKdbxFile(fileData)) {
  console.log('Valid KDBX file!');
}

// Get file info without decrypting
const info = getFileInfo(fileData);
console.log(`Encryption: ${info.encryptionAlgorithm}`);
console.log(`KDF: ${info.kdfAlgorithm}`);

// Open the database
const db = new KdbxDatabase(fileData, 'my-master-password');

// Get database info
console.log('Metadata:', db.metadata);
console.log('Header Info:', db.headerInfo);

// Get all entries
const entries = db.getEntries();
entries.forEach(entry => {
  console.log(`Title: ${entry.title}`);
  console.log(`Username: ${entry.username}`);
  console.log(`Password: ${entry.password}`);
  console.log(`URL: ${entry.url}`);
});

// Search entries
const results = db.searchEntries('google');

// Get entries in a specific group
const groupEntries = db.getEntriesByGroup(db.rootGroupUuid);

// Export to bytes
const exported = db.toBytes('my-master-password');
```

### API Reference

#### `KdbxDatabase`

Main class for working with KDBX databases.

**Constructor**
```typescript
new KdbxDatabase(data: Uint8Array, password?: string, keyFile?: Uint8Array)
```

**Properties**
- `metadata`: Database metadata (name, description, etc.)
- `headerInfo`: Header information (encryption, KDF, counts)
- `rootGroupUuid`: UUID of the root group

**Methods**
- `getEntries()`: Get all entries as an array
- `getEntry(uuid: string)`: Get a specific entry by UUID
- `getGroups()`: Get all groups as an array
- `getGroup(uuid: string)`: Get a specific group by UUID
- `getEntriesByGroup(groupUuid: string)`: Get entries in a specific group
- `searchEntries(query: string)`: Search entries by keyword
- `toBytes(password?: string, keyFile?: Uint8Array)`: Export the database

#### Utility Functions

- `isKdbxFile(data: Uint8Array): boolean`: Check if data is a valid KDBX file
- `getFileInfo(data: Uint8Array): KdbxFileInfo`: Get file info without decrypting

## Building from Source

### Prerequisites

- Rust 1.94.0 or later
- wasm-bindgen-cli

### Build

```bash
# Install wasm-bindgen-cli if not already installed
cargo install wasm-bindgen-cli

# Build the WASM module
.\build-wasm.bat
```

## Browser Compatibility

This library uses WebAssembly and requires a modern browser:

- Chrome 57+
- Firefox 52+
- Safari 11+
- Edge 16+

## Security Considerations

- The master password is used to derive the encryption key
- Key files can be used alongside or instead of passwords
- All cryptographic operations are performed in WebAssembly
- Sensitive data is cleared from memory when possible

## License

MIT
