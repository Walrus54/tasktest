import CryptoKit
import Foundation

enum CryptoError: Error {
    case sealFailed
}

final class Cryptor {

    func encrypt(_ plaintext: Data, key: SymmetricKey) throws -> Data {
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else { throw CryptoError.sealFailed }
        return combined
    }

    func decrypt(_ combined: Data, key: SymmetricKey) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: combined)
        return try AES.GCM.open(box, using: key)
    }
}
