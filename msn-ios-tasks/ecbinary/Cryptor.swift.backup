import CryptoKit
import Foundation
import Security

final class Cryptor {

    private static let keychainAccount = "com.mobsec.ecbinary.aeskey"
    private static let keyByteCount = 32

    private let key: SymmetricKey

    init() {
        self.key = Cryptor.loadOrCreateKey()
    }

    func encrypt(_ plaintext: Data) -> Data {
        guard let sealed = try? AES.GCM.seal(plaintext, using: key),
              let combined = sealed.combined else { return Data() }
        return combined
    }

    func decrypt(_ combined: Data) -> Data {
        guard let box = try? AES.GCM.SealedBox(combined: combined),
              let plaintext = try? AES.GCM.open(box, using: key) else { return Data() }
        return plaintext
    }

    private static func loadOrCreateKey() -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let data = item as? Data, data.count == keyByteCount {
            return SymmetricKey(data: data)
        }

        var newKey = Data(count: keyByteCount)
        let genStatus = newKey.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, keyByteCount, $0.baseAddress!)
        }
        precondition(genStatus == errSecSuccess, "Unable to generate random AES key")

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: keychainAccount,
            kSecValueData as String: newKey,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        SecItemDelete(addQuery as CFDictionary)
        SecItemAdd(addQuery as CFDictionary, nil)
        return SymmetricKey(data: newKey)
    }
}
