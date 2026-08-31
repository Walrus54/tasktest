import CommonCrypto
import Foundation

final class Cryptor {

    private let key: Data

    init() {
        self.key = "my-secret-key-123456789012345".data(using: .utf8)!
    }

    func encrypt(_ plaintext: Data) -> Data {
        let keyBytes = [UInt8](key.prefix(kCCKeySizeAES256))
        let plaintextBytes = [UInt8](plaintext)

        var ciphertextBytes = [UInt8](repeating: 0, count: plaintextBytes.count + kCCBlockSizeAES128)
        var ciphertextLength: Int = 0

        let status = CCCrypt(
            CCOperation(kCCEncrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionECBMode | kCCOptionPKCS7Padding),
            keyBytes,
            kCCKeySizeAES256,
            nil,
            plaintextBytes,
            plaintextBytes.count,
            &ciphertextBytes,
            ciphertextBytes.count,
            &ciphertextLength
        )

        guard status == kCCSuccess else { return Data() }
        return Data(ciphertextBytes.prefix(ciphertextLength))
    }

    func decrypt(_ ciphertext: Data) -> Data {
        let keyBytes = [UInt8](key.prefix(kCCKeySizeAES256))
        let ciphertextBytes = [UInt8](ciphertext)

        var plaintextBytes = [UInt8](repeating: 0, count: ciphertextBytes.count + kCCBlockSizeAES128)
        var plaintextLength: Int = 0

        let status = CCCrypt(
            CCOperation(kCCDecrypt),
            CCAlgorithm(kCCAlgorithmAES),
            CCOptions(kCCOptionECBMode | kCCOptionPKCS7Padding),
            keyBytes,
            kCCKeySizeAES256,
            nil,
            ciphertextBytes,
            ciphertextBytes.count,
            &plaintextBytes,
            plaintextBytes.count,
            &plaintextLength
        )

        guard status == kCCSuccess else { return Data() }
        return Data(plaintextBytes.prefix(plaintextLength))
    }
}
