# Test Fixtures

This directory should contain sample KDBX files for integration testing.

## Required Files

| File | Password | Description |
|------|----------|-------------|
| `test.kdbx` | `test` | Standard KDBX 4 database with a few groups and entries |
| `test_keyfile.kdbx` | `test` + keyfile | Database using password + key file |
| `test_chacha20.kdbx` | `test` | Database using ChaCha20 + Argon2id |

## Generating Fixtures

You can create these files using [KeePass](https://keepass.info/) or [KeePassXC](https://keepassxc.org/).

### Quick Guide (KeePassXC)

1. Create a new database
2. Set the password to `test`
3. Add a few groups (e.g., "Root", "Work", "Personal")
4. Add a few entries with titles, usernames, passwords, URLs, and tags
5. Save as `test.kdbx`

For `test_chacha20.kdbx`:
1. Database → Database Security → Encryption Settings
2. Select "ChaCha20" and "Argon2id"
3. Save

## Running Tests with Fixtures

Once fixtures are in place, remove the `#[ignore]` attribute from:
- `test_parse_pass_kdbx`
- `test_roundtrip_kdbx4`
- `test_hmac_rejects_tampering`

Or run them explicitly:

```bash
cargo test -- --ignored
```
