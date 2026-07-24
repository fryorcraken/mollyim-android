# Recovering the V316 `verified_name_hash` crash by editing the database version

This is a recovery procedure for the crash documented in
[`v316-verified-name-hash-crash.md`](./v316-verified-name-hash-crash.md):
the on-device database has the `groups.verified_name_hash` column while its
recorded `user_version` is below 316, so every launch replays V316's
`ALTER TABLE groups ADD COLUMN verified_name_hash` and crashes.

The idea: the physical schema is already ahead of the app's target schema, so
instead of patching the app, **bump the database's recorded version to the app's
`DATABASE_VERSION` (currently `321`)**. Then `onUpgrade` has no migrations to
run, V316 never fires, and the app opens with all data intact.

> Use this when there is **no backup** and the on-device DB is the only copy.
> Read the whole document before touching anything. Work on copies. Never
> `uninstall` or clear app data — that is the one irreversible, data-destroying
> action.

## What you are changing

```sql
PRAGMA user_version = 321;   -- match the DATABASE_VERSION of the build you will run
```

`321` is `SignalDatabaseMigrations.DATABASE_VERSION` in this tree. Confirm the
value for the exact Molly build you intend to run and use that number. Setting
it equal to that build's version means `onUpgrade` runs nothing.

## Hard prerequisite: root

Molly sets `allowBackup=false` and its data lives in
`/data/data/im.molly.app/`, which is unreadable without **root**. `adb backup`
does not work. If the device is not already rooted, do **not** root it now —
unlocking the bootloader factory-resets the phone and destroys the only copy of
the data.

## The key problem: the SQLCipher key is usually sealed in hardware

The database is SQLCipher-encrypted. The 32-byte key
(`DatabaseSecretProvider`) is stored in one of two ways
(`TextSecurePreferences`):

- `pref_database_unencrypted_secret` — the key in **plaintext hex** (legacy).
- `pref_database_encrypted_secret` — the key **sealed by the Android KeyStore**
  (`KeyStoreHelper`, alias `SignalSecret`, `AES/GCM/NoPadding`, StrongBox where
  available). This is the normal case.

The KeyStore key is **hardware-bound and non-exportable**, so a sealed secret
**cannot be decrypted off-device**. This splits the procedure into two paths.

Check which you have (as root):

```bash
su
cat /data/data/im.molly.app/shared_prefs/*.xml | \
  grep -o 'pref_database_[a-z_]*secret[^/]*'
```

- Found `pref_database_unencrypted_secret` with a value → **Path A** (off-device).
- Only `pref_database_encrypted_secret` → **Path B** (on-device).

> Note: pulling the encrypted `signal.db` off the phone is **not** a portable
> backup when the key is sealed — the key stays in this device's KeyStore, so
> the copied file is unrecoverable if the phone is lost. Treat file copies only
> as same-device rollback. **Once the app opens again, immediately make a real
> Molly backup** so the data stops being single-copy.

## SQLCipher parameters (both paths)

Molly opens the database with these settings (`SqlCipherDatabaseHook` +
`SignalDatabase` passing `DatabaseSecret.asString()`):

- key is the **64-character hex string** passed as a **passphrase** (i.e.
  `PRAGMA key = '<hex>'`, **not** the raw-key `x'...'` form)
- `PRAGMA cipher_compatibility = 3;`
- `PRAGMA kdf_iter = 1;`
- `PRAGMA cipher_page_size = 4096;`

You need a `sqlcipher` build that supports SQLCipher 3 compatibility (SQLCipher
4.x does). The exact open sequence:

```sql
PRAGMA cipher_default_kdf_iter = 1;
PRAGMA cipher_default_page_size = 4096;
PRAGMA key = '<64-hex-char-secret>';
PRAGMA cipher_compatibility = 3;
PRAGMA kdf_iter = 1;
PRAGMA cipher_page_size = 4096;
PRAGMA user_version;          -- sanity: should print a number < 316
```

If `user_version` prints and a `SELECT count(*) FROM groups;` works, the key and
parameters are correct.

---

## Path A — plaintext secret (off-device)

1. **Force-stop the app** (do not uninstall):
   ```bash
   su -c 'am force-stop im.molly.app'
   ```
2. **Read the key** (the hex value of `pref_database_unencrypted_secret`) from
   the shared_prefs XML.
3. **Pull the database and its WAL sidecars** (all three, for consistency):
   ```bash
   su -c 'cp /data/data/im.molly.app/databases/signal.db* /sdcard/'
   adb pull /sdcard/signal.db
   adb pull /sdcard/signal.db-wal   # if present
   adb pull /sdcard/signal.db-shm   # if present
   ```
   Keep an untouched copy of all three as a rollback point.
4. **Edit the version** with `sqlcipher`, then checkpoint the WAL into the main
   file so the change is durable and the sidecars can be dropped:
   ```sql
   -- open with the parameters above, then:
   PRAGMA user_version = 321;
   PRAGMA wal_checkpoint(TRUNCATE);
   ```
   Verify: reopen and confirm `PRAGMA user_version;` prints `321`.
5. **Push back** the edited `signal.db` and **remove the stale sidecars** so the
   old WAL cannot revert your change:
   ```bash
   adb push signal.db /sdcard/signal.db
   su -c 'cp /sdcard/signal.db /data/data/im.molly.app/databases/signal.db'
   su -c 'rm -f /data/data/im.molly.app/databases/signal.db-wal /data/data/im.molly.app/databases/signal.db-shm'
   su -c 'chown u0_a<APP_UID>:u0_a<APP_UID> /data/data/im.molly.app/databases/signal.db'
   su -c 'restorecon /data/data/im.molly.app/databases/signal.db'
   ```
   Get `<APP_UID>` from `su -c 'stat -c %U /data/data/im.molly.app/databases/signal.db'`
   before you start, and reuse the exact owner/SELinux context. Wrong
   ownership or context will make the app fail to open the file.
6. **Launch Molly.** It should open at version 321 with no migration. Then make
   a real Molly backup immediately.

## Path B — sealed secret (on-device, the normal case)

The key cannot leave the device, so do the edit **on-device** by neutralizing
the failing migration at runtime with Frida (root; `frida-server` running):

- **Spawn** Molly under Frida (so you hook before the DB opens):
  ```bash
  frida -U -f im.molly.app -l repair.js --no-pause
  ```
- **Neutralize the collision.** The robust hook is to make the duplicate-column
  `ALTER` a no-op so the whole migration chain completes and the version
  advances to 321 permanently. Conceptually, intercept
  `org.thoughtcrime.securesms.database.SQLiteDatabase.execSQL(String)` and, when
  the statement contains `ADD COLUMN` for a column that already exists, swallow
  it (or catch and ignore the `duplicate column name` `SQLiteException`). This
  is the same effect as the idempotency fix, applied live. After one clean
  start the database is at 321 and the hook is no longer needed.
- Alternatively, hook `DatabaseSecretProvider.getOrCreateDatabaseSecret(...)`
  and log `.asString()` to recover the hex key, then follow **Path A** for the
  file edit. (Only do this if you accept the key leaving the process.)

If a **Molly passphrase** is set and you know it, the secret is additionally
protected by a passphrase-derived key (`MasterSecretUtil` /
`PassphraseBasedKdf`); the key can then be derived with the passphrase, but this
is more involved than the Frida route above.

---

## After recovery

- Confirm the app opens and conversations/groups render.
- **Make a proper Molly backup right away** — the DB is still single-copy until
  you do. That backup, restored onto current Molly, is the durable exit.
- If, after setting `user_version = 321`, the app instead crashes on a
  *different* missing column, the imported Signal schema was *behind* Molly on
  that column. In that case prefer the idempotent-migrations build (guards on
  V316 and the other add-column migrations) so every migration can run and
  either add or skip as appropriate, instead of skipping them all.

## Why this is safe to reason about

- `user_version` lives in the database header; nothing else in the schema or
  data is touched.
- Setting it to the running build's `DATABASE_VERSION` makes
  `SignalDatabaseMigrations.migrate` select zero migrations, so no `ALTER`
  runs and there is nothing to collide with the ahead-of-version schema.
- All destructive risk is in file handling (wrong owner/context, stale WAL) and
  is mitigated by force-stopping first, keeping an untouched copy, checkpointing
  the WAL, and restoring ownership/SELinux context.
