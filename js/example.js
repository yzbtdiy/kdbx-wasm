// Example usage of kdbx-rs WASM module in Node.js
// Note: This requires a Node.js environment with fetch and Uint8Array support

const fs = require('fs');
const path = require('path');

// In a real application, you would import from the package:
// const { KdbxDatabase, isKdbxFile, getFileInfo } = require('kdbx-wasm');

// For this example, we'll show the API usage
async function example() {
  console.log('KDBX Parser Example');
  console.log('==================\n');

  // Example 1: Check if a file is a valid KDBX file
  console.log('1. Checking if file is valid KDBX:');
  // const fileData = fs.readFileSync('passwords.kdbx');
  // const isValid = isKdbxFile(new Uint8Array(fileData));
  // console.log(`   Is valid KDBX: ${isValid}`);

  // Example 2: Get file info without decrypting
  console.log('\n2. Getting file info (without password):');
  // const info = getFileInfo(new Uint8Array(fileData));
  // console.log(`   Version: ${info.version}`);
  // console.log(`   Encryption: ${info.encryptionAlgorithm}`);
  // console.log(`   KDF: ${info.kdfAlgorithm}`);
  // console.log(`   Compression: ${info.compression}`);

  // Example 3: Open the database
  console.log('\n3. Opening database:');
  // const db = new KdbxDatabase(
  //   new Uint8Array(fileData),
  //   'my-master-password',  // optional
  //   undefined              // key file (optional)
  // );

  // Example 4: Get database metadata
  console.log('\n4. Database metadata:');
  // const metadata = db.metadata;
  // console.log(`   Name: ${metadata.databaseName}`);
  // console.log(`   Description: ${metadata.databaseDescription}`);

  // Example 5: Get header info
  console.log('\n5. Header info:');
  // const headerInfo = db.headerInfo;
  // console.log(`   Entries: ${headerInfo.entryCount}`);
  // console.log(`   Groups: ${headerInfo.groupCount}`);
  // console.log(`   Encryption: ${headerInfo.encryptionAlgorithm}`);
  // console.log(`   KDF: ${headerInfo.kdfAlgorithm}`);

  // Example 6: Get all entries
  console.log('\n6. All entries:');
  // const entries = db.getEntries();
  // entries.slice(0, 5).forEach(entry => {
  //   console.log(`   - ${entry.title} (${entry.username})`);
  // });

  // Example 7: Search entries
  console.log('\n7. Search results:');
  // const results = db.searchEntries('google');
  // results.forEach(entry => {
  //   console.log(`   - ${entry.title}: ${entry.username}`);
  // });

  // Example 8: Get entries in root group
  console.log('\n8. Root group entries:');
  // const rootUuid = db.rootGroupUuid;
  // const rootEntries = db.getEntriesByGroup(rootUuid);
  // rootEntries.forEach(entry => {
  //   console.log(`   - ${entry.title}`);
  // });

  // Example 9: Export database
  console.log('\n9. Exporting database:');
  // const exported = db.toBytes('my-master-password');
  // fs.writeFileSync('exported.kdbx', exported);
  // console.log('   Exported to exported.kdbx');

  console.log('\nDone!');
}

example().catch(console.error);
