# Startup crash loop: V316 `verified_name_hash` migration — `duplicate column name`

## Summary

After a Molly update, the app crash-loops on startup while upgrading the
database:

```
FATAL EXCEPTION: signal-bounded-2
android.database.sqlite.SQLiteException: duplicate column name: verified_name_hash (code 1):
  , while compiling: ALTER TABLE groups ADD COLUMN verified_name_hash BLOB DEFAULT NULL
  at ...V316_AddVerifiedGroupNameHashMigration.migrate
  at ...SignalDatabaseMigrations.migrate
  at ...SignalDatabase.onUpgrade
  at ...SignalDatabase.getSignalReadableDatabase
```

The same exception then re-fires from every other thread that opens the
database (`NotificationChannels`, `PendingRetryReceiptManager`,
`RevealableMessageManager`, …), so the database never opens and the app is
unusable.

## Bad database state

The crash requires a database in a state that a normal install or upgrade
**cannot** produce:

- the `groups` table **already has** the `verified_name_hash` column, **and**
- the database's recorded schema version (`PRAGMA user_version`) is still
  **below 316**.

Because migrations run inside a transaction whose version bump only commits on
success (`SignalDatabaseMigrations.migrate`), the `ALTER` failure rolls back
without advancing the version, so V316 is retried on every launch → permanent
crash loop.

## Why normal paths cannot produce it

Verified against the current tree:

- **Fresh install** creates tables from `GroupTable.CREATE_TABLE` (which
  already contains `verified_name_hash`) and records version 321 — V316 never
  runs.
- **In-place upgrade** from an older version: at any version `< 316` the column
  does not yet exist, V316 adds it, and the version advances past 316 in the
  same transaction.
- **No migration below 316 adds the column.** The last `groups` migration
  before it is `V309_GroupTerminatedColumnMigration` (v309, already applied by
  DB v313). `V314` and `V315` do not touch `groups`. Migrations use hardcoded
  SQL, not the live `GroupTable.CREATE_TABLE` constant, so the schema constant
  cannot "leak" the column into an earlier migration.
- **Interrupted migration** cannot leave it either: SQLite DDL is
  transactional, so the `ALTER` and the version bump commit or roll back
  together.

So the column-present-at-version-`< 316` state has to be introduced by
something that sets the schema and the version pointer **from different
sources**.

## Confirmed root cause: importing a newer Signal backup

The reproduction (from the affected user):

1. Installed Molly and **imported a full backup taken from Signal**, which was
   **several database versions ahead** of the Molly being imported into.
2. Signal refuses no such thing, but Molly does: the import path rejects a
   backup whose version is higher than the target DB
   (`FullBackupImporter.processVersion`, throws `DatabaseDowngradeException`).
   To get around this, the user **ran a script to make the Signal backup
   compatible with the older Molly**, which lowered the backup's version frame
   (to a value **below 316**).

### Why this changes the schema

A Signal/Molly full backup is **not data-only**. `FullBackupImporter` replays
the backup's embedded SQL statements verbatim:

- `FullBackupImporter.processStatement` runs `db.execSQL(statement.statement)`
  for each `SqlStatement` frame — including the backup's `CREATE TABLE …`
  DDL (only FTS/emoji/`sqlite_`-internal and excluded key tables are skipped).
- `FullBackupImporter.processVersion` does `db.setVersion(version.version)`
  using the backup's `DatabaseVersion` frame.

Signal, being ahead, wrote the **newer** `groups` schema into the backup:
`CREATE TABLE groups (… verified_name_hash …)`. On import that DDL is executed
verbatim, so the **column is created at import time**. Meanwhile the
version-lowering script set `user_version` **below 316**.

Result: `groups.verified_name_hash` present + `user_version < 316` — exactly
the bad state.

### Why the crash appears "after an update", not at import

Importing into a Molly whose `DATABASE_VERSION` equals the script's chosen
version means no migrations are pending, so the app runs fine. When Molly is
later **updated** to a build with `DATABASE_VERSION = 321`, `onUpgrade` runs
every migration above the stored version — including **V316** — which tries to
add a column the imported schema already has → `duplicate column name` →
crash after the update.

### Answering the user's question directly

> "Could [the compatibility script / data import] have changed my DB schema? I
> thought not."

Yes. Backup import recreates the schema from the DDL embedded in the backup, so
a newer Signal backup imports a **newer schema** even into an older Molly. The
data import is not schema-neutral.

## Why it was effectively unique to this user

This is not a store-build regression that would hit the general user base. It
requires cross-importing a **newer Signal** backup into an **older Molly** and
**hand-editing the backup version** downward so the schema and the version
pointer disagree across the 316 boundary — a bespoke migration path.

## Relevant code

- `app/src/main/java/org/thoughtcrime/securesms/backup/FullBackupImporter.java`
  - `processStatement` (~L185-214): replays backup SQL verbatim, incl. `CREATE TABLE`.
  - `processVersion` (~L177-183): `db.setVersion(backupVersion)`; rejects newer-than-target with `DatabaseDowngradeException`.
- `app/src/main/java/org/thoughtcrime/securesms/database/SignalDatabase.kt`
  - `runPostBackupRestoreTasks` → `onUpgrade(database.version, -1)` after restore.
- `app/src/main/java/org/thoughtcrime/securesms/database/helpers/SignalDatabaseMigrations.kt`
  - `migrate` (~L371): per-version transaction, version bump only on success.
- `app/src/main/java/org/thoughtcrime/securesms/database/helpers/migration/V316_AddVerifiedGroupNameHashMigration.kt`
  - the failing unconditional `ALTER TABLE groups ADD COLUMN verified_name_hash`.
- `app/src/main/java/org/thoughtcrime/securesms/database/GroupTable.kt`
  - `V2_VERIFIED_NAME_HASH` and its presence in `CREATE_TABLE`.

## Fix

Make V316 idempotent — skip the `ALTER` when the column already exists,
matching the pattern already used in `V306_AddRemoteDeletedColumn`, `V196`,
`V186`, `V203`, `V166`:

```kotlin
override fun migrate(context: Application, db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
  if (SqlUtil.columnExists(db, "groups", "verified_name_hash")) {
    Log.i(TAG, "Already have verified_name_hash column!")
    return
  }
  db.execSQL("ALTER TABLE groups ADD COLUMN verified_name_hash BLOB DEFAULT NULL")
}
```

This is a no-op on the normal path. On an affected database it lets V316 pass,
the version advances to 321, and the schema becomes consistent; afterwards any
unpatched build (fork or upstream) opens the repaired database without ever
invoking V316 again.

### Recovery for an already-broken install

- Install a build carrying the idempotent fix, **signed with the same key** as
  the currently installed app (so the update is applied in place and the
  database is preserved). Launch once; the migration completes and the DB is
  repaired to version 321.
- After repair the fix is no longer needed at runtime, so it is safe to return
  to a canonical/unpatched build.

## Note on the compatibility-script approach

Beyond lowering the version frame, a Signal→older-Molly backup can carry other
newer columns/tables in its `CREATE TABLE` DDL. Any such column that a
later Molly migration also adds via an unconditional `ALTER` will hit the same
`duplicate column` failure. A robust import script should either target a
backup version at/above the columns' migration versions, or the affected
migrations should be made idempotent (as done here for V316).
