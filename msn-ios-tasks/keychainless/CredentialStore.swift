import Foundation
import Security

/// Secure credential storage backed by the iOS Keychain.
///
/// Credentials are stored as generic-password Keychain items protected with
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. That protection class keeps
/// the items readable only while the device is unlocked AND excludes them from
/// device backups (iTunes/Finder/iCloud) as well as device-to-device migration.
/// Unlike `UserDefaults`, which is serialized to a plaintext plist that lands in
/// backups verbatim, Keychain items are encrypted by the Secure Enclave / data
/// protection keys and never leak through an unencrypted backup.
final class CredentialStore {

    private let service = "com.example.keychainless.credentials"
    private let tokenAccount = "auth_token"
    private let passwordAccount = "user_password"

    // MARK: - Public API

    func saveToken(_ authToken: String) {
        save(authToken, account: tokenAccount)
    }

    func savePassword(_ password: String) {
        save(password, account: passwordAccount)
    }

    func loadToken() -> String? {
        load(account: tokenAccount)
    }

    func loadPassword() -> String? {
        load(account: passwordAccount)
    }

    func deleteToken() {
        delete(account: tokenAccount)
    }

    func deletePassword() {
        delete(account: passwordAccount)
    }

    // MARK: - Keychain helpers

    private func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    private func save(_ value: String, account: String) {
        guard let data = value.data(using: .utf8) else { return }

        // Idempotent write: drop any existing item, then insert the new one so
        // we never accumulate duplicates or leave stale credentials behind.
        var query = baseQuery(account: account)
        SecItemDelete(query as CFDictionary)

        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(query as CFDictionary, nil)
    }

    private func load(account: String) -> String? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func delete(account: String) {
        SecItemDelete(baseQuery(account: account) as CFDictionary)
    }
}
