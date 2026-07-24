# Recovering from the V316 `verified_name_hash` crash

Recovery procedures for the crash documented in
[`v316-verified-name-hash-crash.md`](./v316-verified-name-hash-crash.md):
the on-device database has the `groups.verified_name_hash` column while its
recorded `user_version` is below 316, so every launch replays V316's
`ALTER TABLE groups ADD COLUMN verified_name_hash` and crashes.

This applies when **there is no backup** and the on-device database is the only
copy of the data. Read the whole document first.

> **The one irreversible action is destroying app data.** Never `uninstall`
> Molly, never "clear data/storage", never factory reset. A *failed*
> `adb install` is harmless and changes nothing — only removal wipes the data.
> Getting a real backup out is the first goal.

## Which strategy

| | Strategy 1 — downgrade + backup | Strategy 2 — DB edit |
|---|---|---|
| Root required | **No** | **Yes** (already rooted; do not root now — it wipes) |
| Needs | USB debugging + a same-signed older APK | root + SQLCipher/Frida |
| Result | app opens, you export a real backup | app opens at version 321 in place |
| Use for | **unrooted devices** | already-rooted devices only |

If the phone is not rooted, use **Strategy 1**. Strategy 2 is kept for rooted
devices.

---

## Strategy 1 — in-place downgrade, then export a backup (no root)

Idea: install an older Molly‑FOSS whose `DATABASE_VERSION` is **below 316**
*over the top* of the current install (data preserved). At that version
`onUpgrade` does not run V316, so the app opens — and you can finally export a
real backup, ending the single-copy risk.

`adb install` does **not** need root, only USB debugging. Every step here is
safe to attempt; a failed install does nothing.

### 1. Enable USB debugging
Developer Options → USB debugging. No root.

### 2. Match the signing key
An in-place reinstall requires the new APK to be signed with the **same key** as
the installed app. Read the installed signer without root:

```bash
adb shell dumpsys package im.molly.app | grep -iA3 "signatures\|signing"
```

Obtain an older **Molly‑FOSS** APK with a **matching** certificate from
**Molly's GitHub releases** (the FOSS variant). Do **not** use the F‑Droid
build (F‑Droid signs with its own key) or the regular Molly build. Verify:

```bash
apksigner verify --print-certs molly-foss-<ver>.apk
```

The certificate SHA‑256 must equal the installed one.

### 3. Pick the version
Choose the **highest Molly‑FOSS release whose `DATABASE_VERSION` is still below
316** (the last release before `verified_name_hash` / V316 landed). That value:

- is **≥** your stored version → no `onDowngrade` error, and
- is **< 316** → V316 does not run.

The exact release must be read from Molly's real release history (this condensed
tree jumps `DATABASE_VERSION` 313 → 321 and does not contain the intermediate
releases). If unsure of the exact one, find it safely by trial — failures are
harmless:

- Install crashes with `duplicate column name: verified_name_hash` → that build
  is **≥ 316**; try an older one.
- App fails to open with `Can't downgrade database from version …` → that
  build's `DATABASE_VERSION` is **below** your stored version; try a newer one.
- App opens normally → correct build.

### 4. Install over the top, keeping data
```bash
adb install -r -d molly-foss-<ver>.apk
```
`-r` reinstall (keep data), `-d` allow version downgrade.

- **Succeeds** → launch Molly; it opens at your current DB version, no V316.
- **Fails on signature** (`INSTALL_FAILED_UPDATE_INCOMPATIBLE`) → wrong
  APK/key; get the matching Molly‑FOSS APK.
- **Fails on downgrade** (`INSTALL_FAILED_VERSION_DOWNGRADE`) → `adb -d`
  downgrade is blocked on this Android build → see *If neither strategy is
  available* below.

### 5. Export a real backup — immediately
In the now-working app: Settings → Chats → Backups (or the local backup
option). Record the backup passphrase. **This is the goal of Strategy 1**: the
data is no longer single-copy.

### 6. Get back to current Molly (durable finish)
Current stock Molly still cannot restore that backup directly — it carries the
ahead-of-version schema stamped at a version below 316, so restoring replays
V316 and crashes identically. Two durable finishes:

- **Re-stamp the backup.** Set the fresh backup's `DatabaseVersion` frame to the
  current build's `DATABASE_VERSION` (321) — the same edit used before — then
  restore into current Molly‑FOSS. `processVersion` accepts it, no migrations
  run, the app opens at 321. (Caveat: assumes the schema is a superset of 321;
  if a Molly-only column is missing, target the schema's true level instead.)
- **Or stay put.** Remain on the downgraded build with Accrescent auto-update
  **off** until an official Molly‑FOSS release carries the idempotency fix, then
  update in place — that update repairs the DB itself.

---

## Strategy 2 — edit the database version (root only)

For an **already-rooted** device: bump the recorded version to the build's
`DATABASE_VERSION` (321) so `onUpgrade` runs no migrations and V316 never
replays.

```sql
PRAGMA user_version = 321;   -- match the DATABASE_VERSION of the build you will run
```

### Prerequisite and the key constraint
Molly's data lives in `/data/data/im.molly.app/` (`allowBackup=false`), so this
needs **root**. The SQLCipher key
(`DatabaseSecretProvider` / `TextSecurePreferences`) is stored as either:

- `pref_database_unencrypted_secret` — key in **plaintext hex** (legacy), or
- `pref_database_encrypted_secret` — key **sealed by the Android KeyStore**
  (`KeyStoreHelper`, alias `SignalSecret`, `AES/GCM/NoPadding`, StrongBox where
  available). This is the normal case, and the key **cannot be extracted
  off-device**.

Check which you have:
```bash
su -c 'grep -o "pref_database_[a-z_]*secret" /data/data/im.molly.app/shared_prefs/*.xml'
```

A copied *sealed* `signal.db` is **not** a portable backup — the key stays in
this device's KeyStore. So after the edit, **make a real Molly backup** too.

### SQLCipher open parameters
Molly opens the database with (`SqlCipherDatabaseHook` + `SignalDatabase`
passing `DatabaseSecret.asString()`):

```sql
PRAGMA cipher_default_kdf_iter = 1;
PRAGMA cipher_default_page_size = 4096;
PRAGMA key = '<64-hex-char-secret>';   -- the hex string as a passphrase, NOT x'...'
PRAGMA cipher_compatibility = 3;
PRAGMA kdf_iter = 1;
PRAGMA cipher_page_size = 4096;
PRAGMA user_version;                    -- sanity: prints a value < 316
```

### Path A — plaintext secret (off-device)
1. `su -c 'am force-stop im.molly.app'` (do **not** uninstall).
2. Read the hex key from `pref_database_unencrypted_secret`.
3. Copy `signal.db` **and** its `-wal`/`-shm` sidecars out; keep an untouched
   copy as rollback.
4. Open with the parameters above, then:
   ```sql
   PRAGMA user_version = 321;
   PRAGMA wal_checkpoint(TRUNCATE);
   ```
   Reopen and confirm `PRAGMA user_version;` prints `321`.
5. Copy the edited `signal.db` back, **delete the stale `-wal`/`-shm`**, and
   restore the original owner and SELinux context:
   ```bash
   su -c 'rm -f /data/data/im.molly.app/databases/signal.db-wal /data/data/im.molly.app/databases/signal.db-shm'
   su -c 'chown <OWNER>:<OWNER> /data/data/im.molly.app/databases/signal.db'
   su -c 'restorecon /data/data/im.molly.app/databases/signal.db'
   ```
   Read `<OWNER>` beforehand with
   `su -c 'stat -c %U /data/data/im.molly.app/databases/signal.db'`.
6. Launch Molly (opens at 321), then export a real backup.

### Path B — sealed secret (on-device, Frida)
The key cannot leave the device. Spawn Molly under Frida (root + `frida-server`)
and neutralize the failing migration at runtime — intercept
`org.thoughtcrime.securesms.database.SQLiteDatabase.execSQL(String)` and swallow
the `ADD COLUMN verified_name_hash` (or catch the `duplicate column name`
exception). The migration chain then completes and the version advances to 321
permanently — the same effect as the idempotency fix, applied live.

---

## If neither strategy is available

(unrooted **and** `adb -d` downgrade blocked, or no same-signed APK)

The only remaining in-place, data-preserving path is an **official Molly‑FOSS
release that carries the idempotency fix**, delivered through the same signed
channel (Accrescent). An in-place update then runs the guarded migrations, each
no-ops on the already-present column, and the version advances to 321.

That is the `V316` idempotency guard in this branch
(`app/src/main/java/org/thoughtcrime/securesms/database/helpers/migration/V316_AddVerifiedGroupNameHashMigration.kt`)
— and, because a newer-Signal backup likely also carries columns that V317–V321
add, the same guard should be extended across the recent add-column migrations
so every one of them is safe to replay.

## Why the version edit is safe to reason about

- `user_version` lives in the database header; no schema or row data is touched.
- Setting it to the running build's `DATABASE_VERSION` makes
  `SignalDatabaseMigrations.migrate` select zero migrations, so no `ALTER` runs
  and nothing can collide with the ahead-of-version schema.
- The residual risk is file handling (owner/SELinux, stale WAL), mitigated by
  force-stopping first, keeping an untouched copy, checkpointing the WAL, and
  restoring ownership and context.
