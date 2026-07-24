# verify-backup-key

Offline **decrypt-test** for a Molly/Signal local-archive backup: proves that a
given **AEP (Backup Key)** + **ACI (account UUID)** actually open a specific
backup, *before* you do anything destructive (uninstall / wipe) to recover from
the [V316 crash](../v316-crash-recovery.md).

This is not a format check. It links the **real Molly libsignal fork** so the key
derivation is byte-for-byte identical to the app's, and it self-tests against
libsignal's own known-answer vector before trusting any result.

## What it checks

Reproduces `LocalArchiver.getBackupId` / `decryptBackupId` (see
`app/.../backup/v2/local/LocalArchiver.kt`):

1. `AEP → BackupKey`         — `BackupKey::derive_from_account_entropy_pool`
2. `BackupKey → metadataKey` — `derive_local_backup_metadata_key` (HKDF)
3. Decrypt the `metadata` frame's encrypted backup id with
   `AES-256-CTR(metadataKey, iv, ctr=0)` → the **stored** backup id.
4. `BackupKey + ACI → expected` backup id — `derive_backup_id` (HKDF over ACI).
5. **stored == expected ⇒ the AEP and ACI are both correct for this backup.**

The equality is authoritative: the metadata key depends only on the AEP, and the
expected id depends on AEP+ACI, so only the true pair makes both sides agree.

> Note: this authenticates the *metadata* (backup id). The `main` archive uses
> `IV || AES-256-CBC(gzip(frames)) || HMAC-SHA256` keyed by
> `MessageBackupKey::derive(backupKey, backupId, None)`; a MATCH here means the
> keys are right, and the on-device restore is the final end-to-end proof.

## Build

The `Cargo.toml` path-depends on a checkout of the **Molly libsignal fork at the
tag matching the app's pinned `im.molly:libsignal-client`** (see
`gradle/libs.versions.toml`, e.g. `0.96.3-1`). Check it out first:

```bash
git clone --depth 1 --branch v0.96.3-1 \
  https://github.com/mollyim/libsignal.git /tmp/libsignal-molly
```

Then adjust the two `path = "/tmp/libsignal-molly/rust/..."` entries in
`Cargo.toml` if you cloned elsewhere or the app bumped libsignal, and:

```bash
cargo build --release
./target/release/verify-backup-key --self-test   # must print: self-test PASSED
```

If the app's libsignal version changed, use the matching fork tag — the
derivation constants (HKDF `info` strings) are version-specific.

## Usage

```bash
# AEP is read from stdin (kept out of shell history); ACI is a CLI arg (not secret).
echo -n '<64-char-AEP>' | ./target/release/verify-backup-key \
    /path/to/SignalBackups/signal-backup-<timestamp>  <ACI-uuid>
```

Prints `✅ MATCH` (safe to proceed) or `❌ NO MATCH` (do **not** wipe).

### Getting your ACI (account UUID)

From a linked Signal **Desktop** on the same account:

- DevTools console (where enabled): `textsecure.storage.user.getAci().toString()`
- Or its SQLCipher DB: `items` table, `id='uuid_id'` (key in `config.json`).

## Related

- [`../v316-crash-recovery.md`](../v316-crash-recovery.md) — the recovery
  playbook and *Session findings*.
- [`../check-aep-key.py`](../check-aep-key.py) — a no-build **format + integrity**
  fallback (validates AEP shape and that the backup directory is well-formed).
  Weaker than this tool: it cannot prove the key decrypts the backup.
