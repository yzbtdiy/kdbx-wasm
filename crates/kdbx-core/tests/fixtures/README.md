# Test Fixtures

This directory contains sample KDBX files for integration testing.

## Files

| File | Password | Description |
|------|----------|-------------|
| `pass.kdbx` | `redhat` | KDBX 4 database used by the parser round-trip tests |

`pass.kdbx` is committed to the repository; the tests in
`crates/kdbx-core/src/core/parser.rs` load it automatically (no `#[ignore]`).

> **Note**: only test data belongs here. Never commit a database containing real credentials.

## Generating Additional Fixtures

You can create more files using [KeePass](https://keepass.info/) or [KeePassXC](https://keepassxc.org/).

### Quick Guide (KeePassXC)

1. Create a new database
2. Set the password to `test`
3. Add a few groups (e.g., "Root", "Work", "Personal")
4. Add entries with titles, usernames, passwords, URLs, tags, expiry dates,
   and attachments (try one with "protect in memory" enabled)
5. Save as `test.kdbx`

For a ChaCha20 variant: Database → Database Security → Encryption Settings →
select "ChaCha20" and "Argon2id", then save as `test_chacha20.kdbx`.
