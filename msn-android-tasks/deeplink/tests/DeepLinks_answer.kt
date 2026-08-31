package com.mobsec.deeplink

/**
 * Password reset links sent by email look like:
 *   https://mobsec.app/reset-password?token=...
 *
 * ResetPasswordActivity (see AndroidManifest.xml) is the intent-filter
 * target for this URL and only this URL — it does not handle the rest of
 * the mobsec.app site.
 */
object DeepLinks {
    const val RESET_PASSWORD_URL = "https://mobsec.app/reset-password"
}
