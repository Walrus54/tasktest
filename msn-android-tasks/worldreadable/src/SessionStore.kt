package com.mobsec.worldreadable.store

import android.content.Context

class SessionStore(private val context: Context) {

    @Suppress("DEPRECATION")
    private fun getPreferences() = context.getSharedPreferences(
        "session",
        Context.MODE_WORLD_READABLE
    )

    fun saveToken(token: String) {
        val prefs = getPreferences()
        prefs.edit()
            .putString("auth_token", token)
            .apply()
    }

    fun loadToken(): String? {
        val prefs = getPreferences()
        return prefs.getString("auth_token", null)
    }
}
