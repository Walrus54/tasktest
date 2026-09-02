import CommonCrypto
import Foundation
import Security

final class Cryptor {

    private let key: Data

    init() {
        self.key = Cryptor.generateRandomKey()
    }

    func encrypt(_ plaintext: Data) -> Data {
        let keyBytes = [UInt8](key.prefix(kCCKeySizeAES256))
        let plaintextBytes = [UInt8](plaintext)

        var iv = [UInt8](repeating: 0, count: kCCBlockSizeAES128)
        let status = SecRandomCopyBytes(kSecRandomDefault, iv.count, &iv)
        guard status == errSecSuccess else { return Data() }

        var ciphertextBytes = [UInt8](repeating: 0, count: plaintextBytes.count + kCCBlockSizeAES128)
        var ciphertextLength: Int = 0

        let cryptStatus = CCCrypt(
            CCOperation(kCCEncrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionPKCS7Padding),
            keyBytes,
            kCCKeySizeAES256,
            iv,
            plaintextBytes,
            plaintextBytes.count,
            &ciphertextBytes,
            ciphertextBytes.count,
            &ciphertextLength
        )

        guard cryptStatus == kCCSuccess else { return Data() }
        return Data(iv) + Data(ciphertextBytes.prefix(ciphertextLength))
    }

    func decrypt(_ ciphertext: Data) -> Data {
        guard ciphertext.count > kCCBlockSizeAES128 else { return Data() }

        let iv = [UInt8](ciphertext.prefix(kCCBlockSizeAES128))
        let actualCiphertext = ciphertext.dropFirst(kCCBlockSizeAES128)

        let keyBytes = [UInt8](key.prefix(kCCKeySizeAES256))
        let ciphertextBytes = [UInt8](actualCiphertext)

        var plaintextBytes = [UInt8](repeating: 0, count: ciphertextBytes.count + kCCBlockSizeAES128)
        var plaintextLength: Int = 0

        let status = CCCrypt(
            CCOperation(kCCDecrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionPKCS7Padding),
            keyBytes,
            kCCKeySizeAES256,
            iv,
            ciphertextBytes,
            ciphertextBytes.count,
            &plaintextBytes,
            plaintextBytes.count,
            &plaintextLength
        )

        guard status == kCCSuccess else { return Data() }
        return Data(plaintextBytes.prefix(plaintextLength))
    }

    private static func generateRandomKey() -> Data {
        var keyData = Data(count: kCCKeySizeAES256)
        let result = keyData.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, kCCKeySizeAES256, $0.baseAddress!)
        }
        precondition(result == errSecSuccess, "Failed to generate random key")
        return keyData
    }
}
