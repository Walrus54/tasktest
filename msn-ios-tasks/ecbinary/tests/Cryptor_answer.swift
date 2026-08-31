import CryptoKit
import Foundation

/// FIXED cryptor.
///
/// Uses AES-GCM (authenticated encryption) with a random nonce generated
/// per call, so encrypting the same plaintext twice yields different
/// ciphertext, and tampering is caught by the authentication tag on decrypt.
/// The key is passed in rather than hardcoded, so callers supply one loaded
/// from the Keychain or derived via a KDF.
enum CryptoError: Error {
    case sealFailed
}

final class Cryptor {

    func encrypt(_ plaintext: Data, key: SymmetricKey) throws -> Data {
        let sealed = try AES.GCM.seal(plaintext, using: key) // random nonce inside
        guard let combined = sealed.combined else { throw CryptoError.sealFailed }
        return combined // nonce || ciphertext || tag
    }

    func decrypt(_ combined: Data, key: SymmetricKey) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: combined)
        return try AES.GCM.open(box, using: key) // verifies the auth tag
    }
}
