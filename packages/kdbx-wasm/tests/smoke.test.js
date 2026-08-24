// Smoke tests for the unified ESM package.
// Node resolves the "node" exports condition to index.js, which loads the
// WASM module synchronously; the browser entry (kdbx_wasm.js) is exercised
// in the last test via its initSync/default export surface.
// Uses the committed fixture at crates/kdbx-core/tests/fixtures/pass.kdbx.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import * as wasm from '../index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const FIXTURE = path.join(
    __dirname,
    '..',
    '..',
    '..',
    'crates',
    'kdbx-core',
    'tests',
    'fixtures',
    'pass.kdbx'
);

test('isKdbxFile / getFileInfo', () => {
    const data = new Uint8Array(fs.readFileSync(FIXTURE));
    assert.strictEqual(wasm.isKdbxFile(data), true);
    assert.strictEqual(wasm.isKdbxFile(new Uint8Array([1, 2, 3])), false);

    const info = wasm.getFileInfo(data);
    assert.match(info.version, /^4\./);
    assert.ok(['AES-256', 'ChaCha20'].includes(info.encryptionAlgorithm));
    assert.ok(['Argon2d', 'Argon2id', 'AES-KDF'].includes(info.kdfAlgorithm));
});

test('open, query, and round-trip export', () => {
    const data = new Uint8Array(fs.readFileSync(FIXTURE));
    const db = new wasm.KdbxDatabase(data, 'redhat');

    const entries = db.getEntries();
    assert.ok(entries.length > 0, 'fixture should contain entries');
    // Passwords excluded by default.
    assert.ok(entries.every((e) => e.password === undefined));

    // Sorted, stable output.
    const titles = entries.map((e) => e.title);
    const sorted = [...titles].sort();
    assert.deepStrictEqual(titles, sorted);

    const withPw = db.getEntries(true);
    assert.ok(withPw.some((e) => typeof e.password === 'string'));

    const groups = db.getGroups();
    assert.ok(groups.length > 0);
    assert.ok(db.rootGroupUuid.length > 0);

    // Export with the same password and re-open.
    const exported = db.toBytes('redhat');
    assert.ok(exported instanceof Uint8Array);
    assert.ok(exported.length > 0);

    const db2 = new wasm.KdbxDatabase(exported, 'redhat');
    assert.strictEqual(db2.headerInfo.entryCount, db.headerInfo.entryCount);
    assert.strictEqual(db2.headerInfo.groupCount, db.headerInfo.groupCount);

    // Wrong password must be rejected.
    assert.throws(() => new wasm.KdbxDatabase(data, 'wrong-password'));
});

test('browser entry surface (kdbx_wasm.js)', async () => {
    const glue = await import('../kdbx_wasm.js');

    // The glue shares one module instance with index.js, so the WASM module
    // is already initialized: initSync must be a safe no-op re-run.
    assert.strictEqual(typeof glue.default, 'function');
    assert.strictEqual(typeof glue.initSync, 'function');
    glue.initSync(fs.readFileSync(path.join(__dirname, '..', 'kdbx_wasm_bg.wasm')));

    const data = new Uint8Array(fs.readFileSync(FIXTURE));
    assert.strictEqual(glue.isKdbxFile(data), true);
    assert.ok(typeof glue.getFileInfo(data).version === 'string');
});
