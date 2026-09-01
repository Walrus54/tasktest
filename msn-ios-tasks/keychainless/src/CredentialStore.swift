import Foundation

final class CredentialStore {

    // MARK: - Public API

    func saveToken(_ authToken: String) {
        UserDefaults.standard.set(authToken, forKey: "auth_token")
    }

    func savePassword(_ password: String) {
        UserDefaults.standard.set(password, forKey: "user_password")
    }

    func loadToken() -> String? {
        UserDefaults.standard.string(forKey: "auth_token")
    }

    func loadPassword() -> String? {
        UserDefaults.standard.string(forKey: "user_password")
    }

    func deleteToken() {
        UserDefaults.standard.removeObject(forKey: "auth_token")
    }

    func deletePassword() {
        UserDefaults.standard.removeObject(forKey: "user_password")
    }
}
