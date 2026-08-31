package com.mobsec.worldreadable.store

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * FIXED session storage.
 *
 * The prefs file is created with MODE_PRIVATE (accessible only to this app)
 * and the token is stored via EncryptedSharedPreferences, backed by a key
 * in the Android Keystore, instead of in plaintext.
 */
class SessionStore(private val context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "session",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveToken(token: String) {
        prefs.edit()
            .putString("auth_token", token)
            .apply()
    }

    fun loadToken(): String? {
        return prefs.getString("auth_token", null)
    }
}
