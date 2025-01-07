package com.encryption

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.annotations.ReactModule
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.WritableMap
import com.facebook.react.bridge.Promise
import javax.crypto.spec.IvParameterSpec
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.spec.RSAPublicKeySpec

import android.util.Base64
import javax.crypto.Cipher
import java.math.BigInteger

import java.security.KeyFactory
import kotlinx.coroutines.*
import kotlin.coroutines.CoroutineContext
import java.io.File

@ReactModule(name = EncryptionModule.NAME)
class EncryptionModule(reactContext: ReactApplicationContext):
    NativeEncryptionSpec(reactContext) {

 // Define a Coroutine Scope for Background Execution
    private val coroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

        override fun getName(): String {
            return NAME
        }

        /**
         * Generates an AES encryption key of specified size.
         *
         * @param keySize The size of the AES key in bits (128, 192, or 256).
         * @return A Base64-encoded AES key.
         * @throws IllegalArgumentException if the key size is invalid.
         * @throws Exception if key generation fails.
         */
        @Throws(IllegalArgumentException::class)
        override fun generateAESKey(keySize: Double): String {
            return AESCryptoUtils.generateAESKey(keySize)
        }

        // -----------------------------------------
        // 🔒 AES Encryption
        // -----------------------------------------

        /**
         * Encrypts plaintext using AES encryption in GCM mode.
         *
         * @param data The plaintext to be encrypted.
         * @param key The Base64-encoded AES key.
         * @return A Base64-encoded string containing the IV and encrypted data.
         * @throws IllegalArgumentException if data or key is invalid.
         * @throws Exception if encryption fails.
         */
        @Throws(IllegalArgumentException::class, Exception::class)
        override fun encryptAES(data: String, key: String): String {
            if (data.isEmpty() || key.isEmpty()) {
                throw IllegalArgumentException("Data or key cannot be empty.")
            }

            return AESCryptoUtils.encrypt(data, key)
        }

        /**
         * Decrypts AES-encrypted data using GCM mode.
         *
         * @param data The Base64-encoded encrypted data (including IV).
         * @param key The Base64-encoded AES key.
         * @return The decrypted plaintext string.
         * @throws IllegalArgumentException if data or key is invalid.
         * @throws Exception if decryption fails.
         */
        @Throws(IllegalArgumentException::class, Exception::class)
        override fun decryptAES(data: String, key: String): String {
            if (data.isEmpty() || key.isEmpty()) {
                throw IllegalArgumentException("Data or key cannot be empty.")
            }

           return AESCryptoUtils.decrypt(data, key)
        }

       /**
     * Asynchronously Encrypts plaintext using AES encryption in GCM mode.
     *
     * @param data The plaintext to be encrypted.
     * @param key The Base64-encoded AES key.
     * @param promise React Native promise to return results or errors.
     */
     @Throws(IllegalArgumentException::class, Exception::class)
     override fun encryptAsyncAES(data: String, key: String, promise: Promise) {
        coroutineScope.launch {
            try {
                val result = AESCryptoUtils.encrypt(data, key)
                promise.resolve(result)
            } catch (e: IllegalArgumentException) {
                promise.reject("ENCRYPTION_ERROR", e.localizedMessage)
            } catch (e: Exception) {
                promise.reject("ENCRYPTION_ERROR", "Unexpected error occurred: ${e.localizedMessage}")
            }
        }
    }

    /**
     * Asynchronously Decrypts AES-encrypted data using GCM mode.
     *
     * @param data The Base64-encoded encrypted data (including IV).
     * @param key The Base64-encoded AES key.
     * @param promise React Native promise to return results or errors.
     */
    @Throws(IllegalArgumentException::class, Exception::class)
    override fun decryptAsyncAES(data: String, key: String, promise: Promise) {
        coroutineScope.launch {
            try {
                val result = AESCryptoUtils.decrypt(data, key)
                promise.resolve(result)
            } catch (e: IllegalArgumentException) {
                promise.reject("DECRYPTION_ERROR", e.localizedMessage)
            } catch (e: Exception) {
                promise.reject("DECRYPTION_ERROR", "Unexpected error occurred: ${e.localizedMessage}")
            }
        }
    }

    /**
 * Asynchronously Encrypts a file using AES-GCM.
 *
 * @param inputPath Path to the input file.
 * @param outputPath Path to save the encrypted file.
 * @param key Base64-encoded AES key.
 * @param promise React Native promise to return results or errors.
 */
@Throws(IllegalArgumentException::class, Exception::class)
override fun encryptFile(inputPath: String, outputPath: String, key: String, promise: Promise) {
    CoroutineScope(Dispatchers.IO).launch {
        try {
            // Read file content
            val inputFile = File(inputPath)
            val inputData = inputFile.readBytes()

            // Encrypt using AESCryptoUtils
            val encryptedData = AESCryptoUtils.encryptBytes(inputData, key)

            // Write encrypted data to output file
            val outputFile = File(outputPath)
            outputFile.writeBytes(encryptedData)

            withContext(Dispatchers.Main) {
                promise.resolve(outputFile.absolutePath)
            }
        } catch (e: IllegalArgumentException) {
            withContext(Dispatchers.Main) {
                promise.reject("FILE_ENCRYPTION_ERROR", e.localizedMessage)
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                promise.reject("FILE_ENCRYPTION_ERROR", "Unexpected error occurred: ${e.localizedMessage}")
            }
        }
    }
}

/**
 * Asynchronously Decrypts an AES-GCM encrypted file.
 *
 * @param inputPath Path to the encrypted file.
 * @param key Base64-encoded AES key.
 * @param promise React Native promise to return results or errors.
 */
@Throws(IllegalArgumentException::class, Exception::class)
override fun decryptFile(inputPath: String, key: String, promise: Promise) {
    CoroutineScope(Dispatchers.IO).launch {
        try {
            // ✅ Step 1: Read the Encrypted File
            val inputFile = File(inputPath)
            if (!inputFile.exists()) {
                withContext(Dispatchers.Main) {
                    promise.reject("DECRYPTION_ERROR", "Input file does not exist at path: $inputPath")
                }
                return@launch
            }

            val encryptedData = inputFile.readBytes()

            // ✅ Step 2: Decrypt File Data using AESCryptoUtils.decryptBytes
            val decryptedData = AESCryptoUtils.decryptBytes(encryptedData, key)

            // ✅ Step 3: Convert Decrypted Data to String
            val decryptedString = String(decryptedData, Charsets.UTF_8)

            // ✅ Step 4: Resolve Promise with Decrypted Content
            withContext(Dispatchers.Main) {
                promise.resolve(decryptedString)
            }

        } catch (e: IllegalArgumentException) {
            withContext(Dispatchers.Main) {
                promise.reject("DECRYPTION_ERROR", e.localizedMessage)
            }
        } catch (e: javax.crypto.AEADBadTagException) {
            withContext(Dispatchers.Main) {
                promise.reject("DECRYPTION_ERROR", "Authentication failed: ${e.localizedMessage}")
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                promise.reject("DECRYPTION_EXCEPTION", "Unexpected error: ${e.localizedMessage}")
            }
        }
    }
}

        // -----------------------------------------
        // 🔑 RSA Key Generation
        // -----------------------------------------

        /**
         * Generates an RSA key pair.
         *
         * @return A WritableMap containing Base64-encoded public and private keys.
         * @throws Exception if key generation fails.
         */
        @Throws(Exception::class)
       override fun generateRSAKeyPair(): WritableMap {
    try {
        // Generate RSA Key Pair
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048)
        val keyPair: KeyPair = keyPairGenerator.genKeyPair()

        // Extract Public and Private Key
        val publicKey = keyPair.public
        val privateKey = keyPair.private

        // Encode Keys to Base64
        val publicKeyBytes = publicKey.encoded
        val privateKeyBytes = privateKey.encoded

        val publicKeyBase64 = Base64.encodeToString(publicKeyBytes, Base64.DEFAULT)
        val privateKeyBase64 = Base64.encodeToString(privateKeyBytes, Base64.DEFAULT)

        // Return as WritableMap
        val result: WritableMap = Arguments.createMap()
        result.putString("publicKey", publicKeyBase64)
        result.putString("privateKey", privateKeyBase64)

        return result
    } catch (e: Exception) {
        e.printStackTrace()
        throw Exception("Failed to generate RSA key pair: ${e.localizedMessage}")
    }
}

        /**
 * Retrieve the Public Key from a given Private Key (Base64 Encoded)
 * @param privateKeyBase64 Base64-encoded RSA private key.
 * @return Base64-encoded RSA public key or null on failure.
 * @throws IllegalArgumentException if the key is invalid.
 * @throws Exception for general key-related errors.
 */
@Throws(IllegalArgumentException::class, Exception::class)
override fun getPublicRSAkey(privateKeyBase64: String): String {
    try {
       // Decode the Base64-encoded private key
        val privateKeyBytes = Base64.decode(privateKeyBase64, Base64.DEFAULT)
        val keySpec = PKCS8EncodedKeySpec(privateKeyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")

        // Generate PrivateKey object
        val privateKey: PrivateKey = keyFactory.generatePrivate(keySpec)
        val rsaPrivateKey = privateKey as java.security.interfaces.RSAPrivateKey

        // Extract Modulus and Public Exponent
        val modulus: BigInteger = rsaPrivateKey.modulus
        val publicExponent: BigInteger = BigInteger.valueOf(65537) // Common RSA exponent

        // Generate PublicKey from Modulus and Public Exponent
        val publicKeySpec = RSAPublicKeySpec(modulus, publicExponent)
        val publicKey: PublicKey = keyFactory.generatePublic(publicKeySpec)

        // Encode PublicKey to Base64
        val publicKeyBase64 = Base64.encodeToString(publicKey.encoded, Base64.DEFAULT)
        return publicKeyBase64

    } catch (e: IllegalArgumentException) {
        throw IllegalArgumentException("Invalid private key format: ${e.localizedMessage}")
    } catch (e: Exception) {
        throw Exception("Failed to extract public key: ${e.localizedMessage}")
    }
}

        // -----------------------------------------
        // 🔒 RSA Encryption
        // -----------------------------------------

        /**
         * Encrypts plaintext using RSA encryption.
         *
         * @param data The plaintext to be encrypted.
         * @param publicKeyBase64 The Base64-encoded RSA public key.
         * @return A Base64-encoded string with encrypted data.
         * @throws IllegalArgumentException if data or key is invalid.
         * @throws Exception if encryption fails.
         */
        @Throws(Exception::class)
        override fun encryptRSA(data: String, publicKeyBase64: String): String ? {
            return try {
                val keyFactory = KeyFactory.getInstance("RSA")
                val publicKeyBytes = Base64.decode(publicKeyBase64, Base64.DEFAULT)
                val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))

                val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
                cipher.init(Cipher.ENCRYPT_MODE, publicKey)

                val encryptedData = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
                Base64.encodeToString(encryptedData, Base64.DEFAULT)
            } catch (e: Exception) {
                e.printStackTrace()
                null
            }
        }

        /**
         * Decrypts RSA-encrypted data.
         *
         * @param data The Base64-encoded encrypted data (including IV).
         * @param privateKeyBase64 The Base64-encoded RSA private key.
         * @return The decrypted plaintext string.
         * @throws IllegalArgumentException if data or key is invalid.
         * @throws Exception if decryption fails.
         */
        @Throws(Exception::class)
        override fun decryptRSA(data: String, privateKeyBase64: String): String ? {
            return try {
                val keyFactory = KeyFactory.getInstance("RSA")
                val privateKeyBytes = Base64.decode(privateKeyBase64, Base64.DEFAULT)
                val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))

                val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
                cipher.init(Cipher.DECRYPT_MODE, privateKey)

                val encryptedData = Base64.decode(data, Base64.DEFAULT)
                String(cipher.doFinal(encryptedData), Charsets.UTF_8)
            } catch (e: Exception) {
                e.printStackTrace()
                null
            }
        }

        /**
         * Encrypts plaintext using RSA encryption.
         *
         * @param data The plaintext to be encrypted.
         * @param publicKeyBase64 The Base64-encoded RSA public key.
         * @return A Base64-encoded string with encrypted data.
         * @throws IllegalArgumentException if data or key is invalid.
         * @throws Exception if encryption fails.
         */
        @Throws(Exception::class)
        override fun encryptAsyncRSA(data: String, publicKeyBase64: String,promise: Promise) {
              coroutineScope.launch {
                 try {
                val keyFactory = KeyFactory.getInstance("RSA")
                val publicKeyBytes = Base64.decode(publicKeyBase64, Base64.DEFAULT)
                val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))

                val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
                cipher.init(Cipher.ENCRYPT_MODE, publicKey)

                  val encryptedData = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
                  promise.resolve(Base64.encodeToString(encryptedData, Base64.DEFAULT))
            } catch (e: Exception) {
                 promise.reject("ENCRYPTION_ERROR", e.localizedMessage)
            }
         }
        }

        /**
         * Decrypts RSA-encrypted data.
         *
         * @param data The Base64-encoded encrypted data (including IV).
         * @param privateKeyBase64 The Base64-encoded RSA private key.
         * @return The decrypted plaintext string.
         * @throws IllegalArgumentException if data or key is invalid.
         * @throws Exception if decryption fails.
         */
        @Throws(Exception::class)
        override fun decryptAsyncRSA(data: String, privateKeyBase64: String,promise: Promise) {
            coroutineScope.launch {
                 try {
                val keyFactory = KeyFactory.getInstance("RSA")
                val privateKeyBytes = Base64.decode(privateKeyBase64, Base64.DEFAULT)
                val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(privateKeyBytes))

                val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
                cipher.init(Cipher.DECRYPT_MODE, privateKey)

                val encryptedData = Base64.decode(data, Base64.DEFAULT)
                
                promise.resolve(String(cipher.doFinal(encryptedData), Charsets.UTF_8))

            } catch (e: Exception) {
                 promise.reject("DECRYPTION_ERROR", e.localizedMessage)
            }
          }
        }

        // -----------------------------------------
        // 🛡️ SHA Hashing
        // -----------------------------------------

        /**
         * Hashes data using SHA-256.
         *
         * @param data The input string to hash.
         * @return A hex-encoded SHA-256 hash.
         * @throws Exception if hashing fails.
         */
        @Throws(Exception::class)
        override fun hashSHA256(data: String): String {
           return HashingUtils.hashSHA256(data)
        }

        /**
         * Hashes data using SHA-512.
         *
         * @param data The input string to hash.
         * @return A hex-encoded SHA-512 hash.
         * @throws Exception if hashing fails.
         */
        @Throws(Exception::class)
        override fun hashSHA512(input: String): String {
            return HashingUtils.hashSHA512(input)
        }

        // -----------------------------------------
        // 📝 HMAC-SHA256/512
        // -----------------------------------------

                /**
 * Generate HMAC Key for SHA-256 or SHA-512.
 * @param keySize Size of the key in bits (256 or 512).
 * @return Base64-encoded HMAC key.
 * @throws IllegalArgumentException If the key size is invalid.
 */
@Throws(IllegalArgumentException::class)
override fun generateHMACKey(keySize: Double): String {
    return HashingUtils.generateHMACKey(keySize)
}
        /**
         * Hashes data using hmac SHA-256.
         *
         * @param data The input string to hash.
         * @param key The input key to be used for hash.
         * @return A hex-encoded hmac SHA-256 hash.
         * @throws Exception if hashing fails.
         */
        @Throws(Exception::class)
        override fun hmacSHA256(data: String, key: String): String {
           return HashingUtils.hmacSHA256(data, key)
        }

         /**
         * Hashes data using hmac SHA-512.
         *
         * @param data The input string to hash.
         * @param key The input key to be used for hash.
         * @return A hex-encoded hmac SHA-256 hash.
         * @throws Exception if hashing fails.
         */
        @Throws(Exception::class)
        override fun hmacSHA512(data: String, key: String): String {
           return HashingUtils.hmacSHA512(data, key)
        }


        // -----------------------------------------
        // 🎲 Random String Generation
        // -----------------------------------------

        /**
         * Generate Random String.
         *
         * @param input The input length to hash.
         * @return A random string.
         * @throws Exception if hashing fails.
         */
        @Throws(Exception::class)
        override fun generateRandomString(input: Double): String {
           return HashingUtils.generateRandomString(input)
        }

        /**
         * Base64 Encode
         * @param input String to encode
         * @return Base64-encoded string
         * @throws Exception if encoding fails
         */
        @Throws(Exception::class)
        override fun base64Encode(input: String): String {
           return HashingUtils.base64Encode(input)
        }

        /**
         * Base64 Decode
         * @param input Base64-encoded string
         * @return Decoded string
         * @throws Exception if decoding fails
         */
        @Throws(Exception::class)
        override fun base64Decode(input: String): String {
           return HashingUtils.base64Decode(input)
        }

        /**
         * Generates an ECDSA (Elliptic Curve Digital Signature Algorithm) key pair.
         *
         * This method generates a 256-bit ECDSA key pair and encodes both the public and private keys
         * into Base64 strings. The keys are returned as a `WritableMap` with `publicKey` and `privateKey` entries.
         *
         * @return WritableMap containing:
         *   - `publicKey`: Base64-encoded ECDSA public key.
         *   - `privateKey`: Base64-encoded ECDSA private key.
         * @throws Exception If the key pair generation fails due to an internal error.
         *
         */
        @Throws(Exception::class)
        override fun generateECDSAKeyPair(): WritableMap {
            return SignatureUtils.generateECDSAKeyPair()
        }

        @Throws(Exception::class)
        override fun getPublicECDSAKey(privateKeyBase64: String): String { 
            return SignatureUtils.getPublicECDSAKey(privateKeyBase64)
        }
        

        /**
         * Signs a given string using ECDSA (Elliptic Curve Digital Signature Algorithm).
         *
         * This method takes input data and a Base64-encoded ECDSA private key to produce
         * a digital signature. The signature ensures data integrity and authenticity.
         *
         * @param data The plaintext data to sign.
         * @param key The Base64-encoded ECDSA private key used for signing.
         *
         * @return A Base64-encoded digital signature string.
         *
         * @throws Exception If signing fails due to invalid key format or other errors.
         *
         */
        @Throws(Exception::class)
        override fun signDataECDSA(data: String, key: String): String {
            return SignatureUtils.signDataECDSA(data,key)
        }

        /**
         * Verifies an ECDSA signature against the provided data and public key.
         *
         * This method takes plaintext data, a digital signature, and a Base64-encoded ECDSA public key.
         * It verifies whether the signature matches the provided data and was signed with the corresponding private key.
         *
         * @param data The original plaintext data.
         * @param signatureBase64 The Base64-encoded digital signature.
         * @param key The Base64-encoded ECDSA public key used for verification.
         *
         * @return `true` if the signature is valid, otherwise `false`.
         *
         * @throws Exception If verification fails due to invalid key format or other errors.
         *
         */
        @Throws(Exception::class)
        override fun verifySignatureECDSA(data: String, signatureBase64: String, key: String): Boolean {
            return SignatureUtils.verifySignatureECDSA(data,signatureBase64,key)
        }

        companion object {
            const val NAME = "Encryption"
            private
            const val TAG = "AESEncryptionModule"
        }
    }