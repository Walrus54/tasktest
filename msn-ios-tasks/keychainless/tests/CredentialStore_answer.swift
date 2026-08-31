import Foundation
import Security

enum KeychainError: Error {
    case unableToStore(OSStatus)
}

/// FIXED credential storage.
///
/// The auth token and password are stored in the Keychain instead of
/// UserDefaults, with kSecAttrAccessibleWhenUnlockedThisDeviceOnly so the
/// items are only available while the device is unlocked and never leave
/// this device (not included in backups/migrations).
final class CredentialStore {

    func saveToken(_ authToken: String) throws {
        try save(authToken, account: "auth_token")
    }

    func savePassword(_ password: String) throws {
        try save(password, account: "user_password")
    }

    func loadToken() -> String? {
        load(account: "auth_token")
    }

    private func save(_ value: String, account: String) throws {
        let data = Data(value.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        SecItemDelete(query as CFDictionary) // overwrite if it already exists
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.unableToStore(status) }
    }

    private func load(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
