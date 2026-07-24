package org.thoughtcrime.securesms.database.helpers.migration

import android.app.Application
import org.signal.core.util.SqlUtil
import org.signal.core.util.logging.Log
import org.thoughtcrime.securesms.database.SQLiteDatabase

@Suppress("ClassName")
object V316_AddVerifiedGroupNameHashMigration : SignalDatabaseMigration {

  private val TAG = Log.tag(V316_AddVerifiedGroupNameHashMigration::class.java)

  override fun migrate(context: Application, db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
    if (SqlUtil.columnExists(db, "groups", "verified_name_hash")) {
      Log.i(TAG, "Already have verified_name_hash column!")
      return
    }

    db.execSQL("ALTER TABLE groups ADD COLUMN verified_name_hash BLOB DEFAULT NULL")
  }
}
