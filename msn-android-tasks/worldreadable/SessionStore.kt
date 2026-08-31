package com.mobsec.worldreadable.store

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

class SessionStore(private val context: Context) {

    private fun getEncryptedPreferences() = EncryptedSharedPreferences.create(
        context,
        "session",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveToken(token: String) {
        val prefs = getEncryptedPreferences()
        prefs.edit()
            .putString("auth_token", token)
            .apply()
    }

    fun loadToken(): String? {
        val prefs = getEncryptedPreferences()
        return prefs.getString("auth_token", null)
    }
}
