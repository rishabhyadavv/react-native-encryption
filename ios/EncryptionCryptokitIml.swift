//
//  EncryptionCryptokitIml.swift
//  react-native-encryption
//
//  Created by Rishabh on 29.12.24.
//

import Foundation
import CryptoKit
import Security

// MARK: - EncryptionError
enum EncryptionError: LocalizedError {
    case invalidData
    case invalidKey
    case invalidKeyLength
    case encryptionFailed
    case decryptionFailed
    case invalidBase64
    case keyGenerationFailed
    case publicKeyExportFailed
    case privateKeyExportFailed
    case keyCreationFailed
    
    var errorDescription: String? {
        switch self {
        case .invalidData:
            return "The provided data is invalid or cannot be processed."
        case .invalidKey:
            return "The encryption key is invalid or cannot be converted."
        case .invalidKeyLength:
            return "The encryption key must be 16, 24, or 32 bytes long."
        case .encryptionFailed:
            return "AES encryption failed due to an internal error."
        case .decryptionFailed:
            return "AES decryption failed due to an internal error."
        case .invalidBase64:
            return "The provided Base64 string is invalid or cannot be decoded."
        case .keyGenerationFailed:
            return "Failed to generate a secure encryption key."
        case .publicKeyExportFailed:
            return "Failed to export the public key."
        case .privateKeyExportFailed:
            return "Failed to export the private key."
        case .keyCreationFailed:
            return "Failed to create an encryption key from the given data."
        }
    }
}

// MARK: - CryptoUtility
@objcMembers
public class CryptoUtility: NSObject {
    
    /// Generate a AES base64 key as string
    /// - Parameters:
    ///   - keySize: Size of the key i.e 128,192, or 256.
    /// - Returns: Base64-encoded encrypted string or nil on failure.
    @objc public func generateAESKey(_ keySize: Int) -> String {
        let key: SymmetricKey
        
        switch keySize {
        case 128:
            key = SymmetricKey(size: .bits128)
        case 192:
            key = SymmetricKey(size: .bits192)
        case 256:
            key = SymmetricKey(size: .bits256)
        default:
            fatalError("Invalid AES key size. Must be 128, 192, or 256 bits.")
        }
        
        let keyData = key.withUnsafeBytes { Data(Array($0)) }
        return keyData.base64EncodedString()
    }
    
    // MARK: - AES Encryption Helper

    /// Shared method for AES encryption logic.
    /// - Parameters:
    ///   - data: Data to be encrypted.
    ///   - key: Base64-encoded AES key.
    /// - Throws: EncryptionError
    /// - Returns: Encrypted data as `Data`
    private func performAESEncryption(data: Data, key: String) throws -> Data {
        // Validate Key
        guard let keyData = Data(base64Encoded: key) else {
            throw EncryptionError.invalidKey
        }
        
        // Initialize Symmetric Key
        let symmetricKey = SymmetricKey(data: keyData)
        
        // Encrypt Data
        let sealedBox = try AES.GCM.seal(data, using: symmetricKey)
        guard let combinedData = sealedBox.combined else {
            throw EncryptionError.encryptionFailed
        }
        
        return combinedData
    }

    // MARK: - AES Encryption for String

    /// Encrypts a string using AES with a Base64 public key.
    /// - Parameters:
    ///   - data: Plain text string to be encrypted.
    ///   - key: Base64-encoded AES key.
    ///   - errorObj: NSErrorPointer for capturing errors.
    /// - Returns: Base64-encoded encrypted string or nil on failure.
    @objc public func encryptAES(_ data: String, key: String, errorObj: NSErrorPointer) -> String? {
        do {
            // Convert string to data
            guard let dataToEncrypt = data.data(using: .utf8) else {
                throw EncryptionError.invalidData
            }
            
            // Perform encryption
            let encryptedData = try performAESEncryption(data: dataToEncrypt, key: key)
            return encryptedData.base64EncodedString()
            
        } catch let encryptionError as EncryptionError {
            errorObj?.pointee = NSError(
                domain: "CryptoUtility",
                code: -1,
                userInfo: [
                    NSLocalizedDescriptionKey: encryptionError.localizedDescription
                ]
            )
            return nil
        } catch {
            errorObj?.pointee = NSError(
                domain: "CryptoUtility",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "An unknown encryption error occurred."]
            )
            return nil
        }
    }

    // MARK: - AES Encryption for File

    /// Encrypts a file using AES with a Base64 public key.
    /// - Parameters:
    ///   - inputPath: Path to the input file.
    ///   - outputPath: Path to save the encrypted file.
    ///   - key: Base64-encoded AES key.
    ///   - errorObj: NSErrorPointer for capturing errors.
    /// - Returns: Path to the encrypted file or nil on failure.
    @objc public func encryptFile(_ inputPath: String, outputPath: String, key: String, errorObj: NSErrorPointer) -> String? {
        do {
            // Validate file paths
            let inputURL = URL(fileURLWithPath: inputPath)
            let outputURL = URL(fileURLWithPath: outputPath)
            
            // Read file data
            let fileData = try Data(contentsOf: inputURL)
            
            // Perform encryption
            let encryptedData = try performAESEncryption(data: fileData, key: key)
            
            // Write encrypted data to output file
            try encryptedData.write(to: outputURL)
            
            return outputURL.path
            
        } catch let encryptionError as EncryptionError {
            errorObj?.pointee = NSError(
                domain: "CryptoUtility",
                code: -1,
                userInfo: [
                    NSLocalizedDescriptionKey: encryptionError.localizedDescription
                ]
            )
            return nil
        } catch {
            errorObj?.pointee = NSError(
                domain: "CryptoUtility",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "An unknown encryption error occurred."]
            )
            return nil
        }
    }
    
    
    private func performAESDecryption(data: Data, key: String) throws -> Data {
        // Validate Key
        guard let keyData = Data(base64Encoded: key) else {
            throw EncryptionError.invalidKey
        }
        
        // Initialize Symmetric Key
        let symmetricKey = SymmetricKey(data: keyData)
        
        // Decrypt Data
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        let decryptedData = try AES.GCM.open(sealedBox, using: symmetricKey)
        
        return decryptedData
    }

    // MARK: - AES Decryption for String

    /// Decrypts a Base64-encoded encrypted string using AES.
    /// - Parameters:
    ///   - data: Base64-encoded encrypted string.
    ///   - key: Base64-encoded AES key.
    ///   - errorObj: NSErrorPointer for capturing errors.
    /// - Returns: Decrypted plain text string or nil on failure.
    @objc public func decryptAES(_ data: String, key: String, errorObj: NSErrorPointer) -> String? {
        do {
            // Decode Base64-encoded data
            guard let encryptedData = Data(base64Encoded: data) else {
                throw EncryptionError.invalidData
            }
            
            // Perform decryption
            let decryptedData = try performAESDecryption(data: encryptedData, key: key)
            
            // Convert to String
            guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
                throw EncryptionError.decryptionFailed
            }
            
            return decryptedString
            
        } catch let decryptionError as EncryptionError {
            errorObj?.pointee = NSError(
                domain: "CryptoUtility",
                code: -1,
                userInfo: [
                    NSLocalizedDescriptionKey: decryptionError.localizedDescription
                ]
            )
            return nil
        } catch {
            errorObj?.pointee = NSError(
                domain: "CryptoUtility",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "An unknown decryption error occurred."]
            )
            return nil
        }
    }

    // MARK: - AES Decryption for File

    /// Decrypts an AES-encrypted file using a Base64-encoded AES key.
    /// - Parameters:
    ///   - inputPath: Path to the encrypted input file.
    ///   - key: Base64-encoded AES key.
    ///   - errorObj: NSErrorPointer for capturing errors.
    /// - Returns: Decrypted data as a string or nil on failure.
    @objc public func decryptFile(_ inputPath: String, key: String, errorObj: NSErrorPointer) -> String? {
        do {
            // Validate File Path
            let inputURL = URL(fileURLWithPath: inputPath)
            
            // Read Encrypted File Data
            let encryptedData = try Data(contentsOf: inputURL)
            
            // Perform decryption
            let decryptedData = try performAESDecryption(data: encryptedData, key: key)
            
            // Convert to String
            guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
                throw EncryptionError.decryptionFailed
            }
            
            return decryptedString
            
        } catch let decryptionError as EncryptionError {
            errorObj?.pointee = NSError(
                domain: "CryptoUtility",
                code: -1,
                userInfo: [
                    NSLocalizedDescriptionKey: decryptionError.localizedDescription
                ]
            )
            return nil
        } catch {
            errorObj?.pointee = NSError(
                domain: "CryptoUtility",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "An unknown decryption error occurred."]
            )
            return nil
        }
    }
    
    private func constructSecKey(from keyBase64: String, isPublicKey: Bool) throws -> SecKey {
            guard let keyData = Data(base64Encoded: keyBase64) else {
                throw EncryptionError.invalidKey
            }
            
            let keyClass = isPublicKey ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate
            let keyAttributes: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: keyClass,
                kSecAttrKeySizeInBits as String: 2048
            ]
            
            var error: Unmanaged<CFError>?
            guard let secKey = SecKeyCreateWithData(keyData as CFData,
                                                    keyAttributes as CFDictionary,
                                                    &error) else {
                throw error?.takeRetainedValue() ?? EncryptionError.keyCreationFailed
            }
            
            return secKey
        }
    

        
        // MARK: - RSA Encryption
        
        /// Encrypts a string using RSA with a Base64 public key.
        /// - Parameters:
        ///   - data: Plain text string to be encrypted.
        ///   - publicKeyBase64: Base64-encoded RSA public key.
        ///   - errorObj: NSErrorPointer for capturing errors.
        /// - Returns: Base64-encoded encrypted string or nil on failure.
        @objc public func encryptRSA(_ data: String, publicKeyBase64: String, errorObj: NSErrorPointer) -> String? {
            do {
                // Create Public Key from Base64 String
                let publicKey = try constructSecKey(from: publicKeyBase64, isPublicKey: true)
                
                // Validate Data
                guard let dataToEncrypt = data.data(using: .utf8) else {
                    throw EncryptionError.invalidData
                }
                
                // Encrypt Data using RSA
                var error: Unmanaged<CFError>?
                guard let encryptedData = SecKeyCreateEncryptedData(
                    publicKey,
                    .rsaEncryptionPKCS1,
                    dataToEncrypt as CFData,
                    &error
                ) as Data? else {
                    throw error?.takeRetainedValue() ?? EncryptionError.encryptionFailed
                }
                
                return encryptedData.base64EncodedString()
            } catch let encryptionError as EncryptionError {
                errorObj?.pointee = NSError(
                    domain: "CryptoUtility",
                    code: -1,
                    userInfo: [
                        NSLocalizedDescriptionKey: encryptionError.localizedDescription
                    ]
                )
                return nil
            } catch {
                errorObj?.pointee = NSError(
                    domain: "CryptoUtility",
                    code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "An unknown RSA encryption error occurred."]
                )
                return nil
            }
        }
    
    @objc public func generateRSAKeyPair(_ errorObj: NSErrorPointer) -> NSDictionary? {
            do {
                let keySize = 2048
                
                // Define Key Attributes
                let attributes: [String: Any] = [
                    kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                    kSecAttrKeySizeInBits as String: keySize,
                    kSecPrivateKeyAttrs as String: [
                        kSecAttrIsPermanent as String: false
                    ],
                    kSecPublicKeyAttrs as String: [
                        kSecAttrIsPermanent as String: false
                    ]
                ]
                
                // Generate Private Key
                var error: Unmanaged<CFError>?
                guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                    throw error?.takeRetainedValue() ?? EncryptionError.keyGenerationFailed
                }
                
                // Extract Public Key
                guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
                    throw EncryptionError.publicKeyExportFailed
                }
                
                // Export Public Key
                guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
                    throw error?.takeRetainedValue() ?? EncryptionError.publicKeyExportFailed
                }
                
                // Export Private Key
                guard let privateKeyData = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else {
                    throw error?.takeRetainedValue() ?? EncryptionError.privateKeyExportFailed
                }
                
                // Encode Keys as Base64
                let publicKeyBase64 = publicKeyData.base64EncodedString()
                let privateKeyBase64 = privateKeyData.base64EncodedString()
                
                return [
                    "publicKey": publicKeyBase64,
                    "privateKey": privateKeyBase64
                ]
                
            }  catch let err as NSError {
                if let errorPointer = errorObj {
                    errorPointer.pointee = err
                }
                return nil
            }
            catch {
                if let errorPointer = errorObj {
                    errorPointer.pointee = NSError(domain: "com.example.encryption",
                                                   code: -1,
                                                   userInfo: [NSLocalizedDescriptionKey: "An unknown error occurred: \(error.localizedDescription)"])
                }
                return nil
            }
        }
        
        // MARK: - RSA Decryption
        
        /// Decrypts a Base64-encoded string using RSA with a Base64 private key.
        /// - Parameters:
        ///   - data: Base64-encoded encrypted string.
        ///   - privateKeyBase64: Base64-encoded RSA private key.
        ///   - errorObj: NSErrorPointer for capturing errors.
        /// - Returns: Decrypted plain text string or nil on failure.
        @objc public func decryptRSA(_ data: String, privateKeyBase64: String, errorObj: NSErrorPointer) -> String? {
            do {
                // Create Private Key from Base64 String
                let privateKey = try constructSecKey(from: privateKeyBase64, isPublicKey: false)
                
                // Validate Base64 Data
                guard let encryptedData = Data(base64Encoded: data) else {
                    throw EncryptionError.invalidBase64
                }
                
                // Decrypt Data using RSA
                var error: Unmanaged<CFError>?
                guard let decryptedData = SecKeyCreateDecryptedData(
                    privateKey,
                    .rsaEncryptionPKCS1,
                    encryptedData as CFData,
                    &error
                ) as Data? else {
                    throw error?.takeRetainedValue() ?? EncryptionError.decryptionFailed
                }
                
                // Convert Decrypted Data to String
                guard let decryptedString = String(data: decryptedData, encoding: .utf8) else {
                    throw EncryptionError.decryptionFailed
                }
                
                return decryptedString
            } catch let decryptionError as EncryptionError {
                errorObj?.pointee = NSError(
                    domain: "CryptoUtility",
                    code: -1,
                    userInfo: [
                        NSLocalizedDescriptionKey: decryptionError.localizedDescription
                    ]
                )
                return nil
            } catch {
                errorObj?.pointee = NSError(
                    domain: "CryptoUtility",
                    code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "An unknown RSA decryption error occurred."]
                )
                return nil
            }
        }
    
    // MARK: - Hashing (SHA256 & SHA512)
    
    /// Generate a hashSHA256 base64 key as string
    /// - Parameters:
    ///   - input: string value.
    /// - Returns: Hashed value as string.
    @objc public func hashSHA256(_ input: String) -> String {
        let data = Data(input.utf8)
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
    
    /// Generate a hashSHA512 base64 key as string
    /// - Parameters:
    ///   - input: string value.
    /// - Returns: Hashed value as string.
    @objc public func hashSHA512(_ input: String) -> String {
        let data = Data(input.utf8)
        let digest = SHA512.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
    
    // MARK: - HMAC (SHA256)
    
    /// Create base64 string using hmacSHA256 .
    /// - Parameters:
    ///   - data: Plain text string to be encrypted.
    ///   - key: Base64-encoded   key.
    ///   - errorObj: NSErrorPointer for capturing errors.
    /// - Returns: Base64-encoded encrypted string or nil on failure.
    @objc public func hmacSHA256(_ data: String, key: String, errorObj:NSErrorPointer) -> String? {
        do {
            // Decode the Base64 key
            guard let keyData = key.data(using: .utf8) else {
                throw EncryptionError.invalidKey
            }
            
            // Create SymmetricKey
            let symmetricKey = SymmetricKey(data: keyData)
            
            // Convert the input data to bytes
            let dataBytes = Data(data.utf8)
            
            // Generate HMAC
            let authenticationCode = HMAC<SHA256>.authenticationCode(for: dataBytes, using: symmetricKey)
            
            // Convert to hex string
            let hmacString = authenticationCode.map { String(format: "%02x", $0) }.joined()
            return hmacString
        }  catch let encryptionError as EncryptionError {
            errorObj?.pointee = NSError(
                domain: "CryptoUtility",
                code: -1,
                userInfo: [
                    NSLocalizedDescriptionKey: encryptionError.localizedDescription
                ]
            )
            return nil
        } catch {
            errorObj?.pointee = NSError(
                domain: "CryptoUtility",
                code: -1,
                userInfo: [
                    NSLocalizedDescriptionKey: "Unknown error ocuured"
                ]
            )
            return nil
        }
    }
    
    // MARK: - Random String Generation
    /// Generate random  string .
    /// - Parameters:
    ///   - length: Plain text string to be encrypted.
    ///   - errorObj: NSErrorPointer for capturing errors.
    /// - Returns: random string or nil on failure.
    @objc public func generateRandomString(_ length: Int, errorObj: NSErrorPointer) -> String? {
        // Validate Input
        guard length > 0 else {
            errorObj?.pointee = NSError(
                domain: "RandomStringError",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "Length must be greater than zero"]
            )
            return nil
        }
        
        let charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        let charsetArray = Array(charset)
        let charsetCount = charsetArray.count
        
        var randomString = ""
        var buffer = [UInt8](repeating: 0, count: length)
        
        let result = SecRandomCopyBytes(kSecRandomDefault, length, &buffer)
        if result != errSecSuccess {
            errorObj?.pointee = NSError(
                domain: "RandomStringError",
                code: -2,
                userInfo: [NSLocalizedDescriptionKey: "Failed to generate secure random bytes"]
            )
            return nil
        }
        
        for byte in buffer {
            randomString.append(charsetArray[Int(byte) % charsetCount])
        }
        
        return randomString
    }
    
    // MARK: - Base64 Encoding & Decoding
    /// Encode a plain text to base64
    /// - Parameters:
    ///   - input: string value.
    /// - Returns: Encoded value as string.
    @objc public func base64Encode(_ input: String) -> String {
        return Data(input.utf8).base64EncodedString()
    }
    
    /// Decode a plain text to base64
    /// - Parameters:
    ///   - input: string value.
    /// - Returns: decoded value as plain text string.
    @objc public func base64Decode(_ input: String,errorObj:NSErrorPointer) -> String? {
        do {
            guard let data = Data(base64Encoded: input),
                  let decodedString = String(data: data, encoding: .utf8) else {
                throw EncryptionError.invalidBase64
            }
            
            return decodedString
            
        } catch let err as NSError {
            if let errorPointer = errorObj {
                errorPointer.pointee = err
            }
            return nil
        }
        catch {
            if let errorPointer = errorObj {
                errorPointer.pointee = NSError(domain: "com.example.encryption",
                                               code: -1,
                                               userInfo: [NSLocalizedDescriptionKey: "An unknown error occurred: \(error.localizedDescription)"])
            }
            return nil
        }
    
   }
    
    /// Generate a public/private key pair for ECDSA
    /// - Returns: public/private key pair for ECDSA as dictionary
    @objc public func generateECDSAKeyPair() -> NSDictionary {
        let privateKey = P256.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        
        let privateKeyData = privateKey.rawRepresentation.base64EncodedString()
        let publicKeyData = publicKey.rawRepresentation.base64EncodedString()
        
        return [
            "publicKey": publicKeyData,
            "privateKey": privateKeyData
        ]
    }
    
    // MARK: - Sign Data using ECDSA
        
        /// Sign data using ECDSA private key
        /// - Parameters:
        ///   - data: The plain text data to sign.
        ///   - privateKeyBase64: Base64-encoded private key.
        ///   - errorObj: NSErrorPointer for capturing errors.
        /// - Returns: Base64-encoded signature string.
        @objc public func signDataECDSA(_ data: String, privateKeyBase64: String, errorObj: NSErrorPointer) -> String? {
            do {
                guard let privateKeyData = Data(base64Encoded: privateKeyBase64) else {
                    throw EncryptionError.invalidKey
                }
                let privateKey = try P256.Signing.PrivateKey(rawRepresentation: privateKeyData)
                
                let dataToSign = Data(data.utf8)
                let signature = try privateKey.signature(for: dataToSign)
                return signature.derRepresentation.base64EncodedString()
            } catch let encryptionError as EncryptionError {
                errorObj?.pointee = NSError(
                    domain: "CryptoUtility",
                    code: -1,
                    userInfo: [NSLocalizedDescriptionKey: encryptionError.localizedDescription]
                )
                return nil
            } catch {
                errorObj?.pointee = NSError(
                    domain: "CryptoUtility",
                    code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "An unknown signing error occurred."]
                )
                return nil
            }
        }
        
        // MARK: - Verify Signature using ECDSA
        
        /// Verify ECDSA signature
        /// - Parameters:
        ///   - data: The plain text data.
        ///   - signatureBase64: Base64-encoded signature.
        ///   - publicKeyBase64: Base64-encoded public key.
        ///   - errorObj: NSErrorPointer for capturing errors.
        /// - Returns: Boolean indicating signature validity.
        @objc public func verifySignatureECDSA(_ data: String, signatureBase64: String, publicKeyBase64: String, errorObj: NSErrorPointer) -> Bool {
            do {
                guard let publicKeyData = Data(base64Encoded: publicKeyBase64),
                      let signatureData = Data(base64Encoded: signatureBase64) else {
                    throw EncryptionError.invalidKey
                }
                let publicKey = try P256.Signing.PublicKey(rawRepresentation: publicKeyData)
                let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureData)
                
                let dataToVerify = Data(data.utf8)
                return publicKey.isValidSignature(signature, for: dataToVerify)
            } catch let encryptionError as EncryptionError {
                errorObj?.pointee = NSError(
                    domain: "CryptoUtility",
                    code: -1,
                    userInfo: [NSLocalizedDescriptionKey: encryptionError.localizedDescription]
                )
                return false
            } catch {
                errorObj?.pointee = NSError(
                    domain: "CryptoUtility",
                    code: -1,
                    userInfo: [NSLocalizedDescriptionKey: "An unknown verification error occurred."]
                )
                return false
            }
        }
}

