package com.encryption

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.annotations.ReactModule
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.WritableMap
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import android.util.Base64
import kotlin.math.roundToInt
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.Signature
import java.security.KeyFactory

@ReactModule(name = EncryptionModule.NAME)
class EncryptionModule(reactContext: ReactApplicationContext):
    NativeEncryptionSpec(reactContext) {

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
            val validKeySizes = setOf(128, 192, 256)
            if (keySize.toInt() !in validKeySizes) {
                throw IllegalArgumentException("Invalid AES key size. Must be 128, 192, or 256 bits.")
            }

            return try {
                val keyGenerator = KeyGenerator.getInstance("AES")
                keyGenerator.init(keySize.toInt())
                val secretKey: SecretKey = keyGenerator.generateKey()
                val keyBytes = secretKey.encoded
                Base64.encodeToString(keyBytes, Base64.DEFAULT)
            } catch (e: Exception) {
                throw IllegalArgumentException("Failed to generate AES key: ${e.localizedMessage}", e)
            }
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

            // Decode the key from Base64
            val keyBytes =
                try {
                    Base64.decode(key, Base64.DEFAULT)
                } catch (e: Exception) {
                    throw IllegalArgumentException("Invalid AES key format: ${e.localizedMessage}")
                }

            // Validate key length
            if (keyBytes.size != 16 && keyBytes.size != 24 && keyBytes.size != 32) {
                throw IllegalArgumentException("Invalid AES key size. Must be 16, 24, or 32 bytes (128, 192, or 256 bits).")
            }

            // Generate Initialization Vector (IV)
            val iv = ByteArray(16)
            SecureRandom().nextBytes(iv)
            val ivSpec = IvParameterSpec(iv)

            // Initialize Cipher
            val secretKey = SecretKeySpec(keyBytes, "AES")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)

            // Encrypt Data
            val encryptedData = cipher.doFinal(data.toByteArray(Charsets.UTF_8))

            // Combine IV and Encrypted Data
            val combined = iv + encryptedData

            // Return as Base64 String
            return Base64.encodeToString(combined, Base64.DEFAULT)
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

            // Decode the AES key from Base64
            val keyBytes =
                try {
                    Base64.decode(key, Base64.DEFAULT)
                } catch (e: Exception) {
                    throw IllegalArgumentException("Invalid AES key format: ${e.localizedMessage}")
                }

            // Validate key length
            if (keyBytes.size != 16 && keyBytes.size != 24 && keyBytes.size != 32) {
                throw IllegalArgumentException("Invalid AES key size. Must be 16, 24, or 32 bytes (128, 192, or 256 bits).")
            }

            // Decode the encrypted data from Base64
            val decodedData =
                try {
                    Base64.decode(data, Base64.DEFAULT)
                } catch (e: Exception) {
                    throw IllegalArgumentException("Invalid encrypted data format: ${e.localizedMessage}")
                }

            // Extract IV and encrypted data
            if (decodedData.size < 16) {
                throw IllegalArgumentException("Invalid encrypted data. Data too short to contain IV.")
            }

            val iv = decodedData.copyOfRange(0, 16)
            val encryptedBytes = decodedData.copyOfRange(16, decodedData.size)
            val ivSpec = IvParameterSpec(iv)

            // Initialize Cipher for AES decryption
            val secretKey = SecretKeySpec(keyBytes, "AES")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)

            // Decrypt and return as String
            return String(cipher.doFinal(encryptedBytes), Charsets.UTF_8)
        }

        // -----------------------------------------
        // 🔑 AES Key Generation
        // -----------------------------------------

        /**
         * Generates an RSA key pair.
         *
         * @return A WritableMap containing Base64-encoded public and private keys.
         * @throws Exception if key generation fails.
         */
        @Throws(Exception::class)
        override fun generateRSAKeyPair(): WritableMap {
            return try {
                // Generate RSA Key Pair
                val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
                keyPairGenerator.initialize(2048)
                val keyPair = keyPairGenerator.genKeyPair()

                // Get keys and encode them as Base64
                val publicKey = keyPair.public.encoded
                val privateKey = keyPair.private.encoded

                val publicKeyBase64 = Base64.encodeToString(publicKey, Base64.DEFAULT)
                val privateKeyBase64 = Base64.encodeToString(privateKey, Base64.DEFAULT)

                // Create WritableMap
                val result: WritableMap = Arguments.createMap()
                result.putString("publicKey", publicKeyBase64)
                result.putString("privateKey", privateKeyBase64)

                result
            } catch (e: Exception) {
                e.printStackTrace()
                val errorMap: WritableMap = Arguments.createMap()
                errorMap.putString("error", "Failed to generate RSA key pair: ${e.localizedMessage}")
                errorMap
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
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(data.toByteArray())
            return hash.joinToString("") {
                "%02x".format(it)
            }
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
            if (input.isEmpty()) {
                throw IllegalArgumentException("Input string cannot be empty for SHA-512 hashing")
            }

            val bytes = input.toByteArray(Charsets.UTF_8)
            val md = MessageDigest.getInstance("SHA-512")
            val digest = md.digest(bytes)

            // Convert to hex string
            return digest.joinToString("") {
                "%02x".format(it)
            }
        }

        // -----------------------------------------
        // 📝 HMAC-SHA256
        // -----------------------------------------

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
            val secretKey = SecretKeySpec(key.toByteArray(), "HmacSHA256")
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(secretKey)
            val hash = mac.doFinal(data.toByteArray())
            return hash.joinToString("") {
                "%02x".format(it)
            }
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
            val length = input.roundToInt()
            if (length <= 0) {
                throw IllegalArgumentException("Length must be a positive number.")
            }

            val charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            val random = SecureRandom()
            return (1..length)
                .map {
                    charset[random.nextInt(charset.length)]
                }
                .joinToString("")
        }

        /**
         * Base64 Encode
         * @param input String to encode
         * @return Base64-encoded string
         * @throws Exception if encoding fails
         */
        @Throws(Exception::class)
        override fun base64Encode(input: String): String {
            if (input.isEmpty()) {
                throw IllegalArgumentException("Input string cannot be empty for Base64 encoding")
            }

            return try {
                Base64.encodeToString(input.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
            } catch (e: Exception) {
                throw Exception("Failed to encode Base64: ${e.message}")
            }
        }

        /**
         * Base64 Decode
         * @param input Base64-encoded string
         * @return Decoded string
         * @throws Exception if decoding fails
         */
        @Throws(Exception::class)
        override fun base64Decode(input: String): String {
            if (input.isEmpty()) {
                throw IllegalArgumentException("Input string cannot be empty for Base64 decoding")
            }

            return try {
                val decodedBytes = Base64.decode(input, Base64.NO_WRAP)
                String(decodedBytes, Charsets.UTF_8)
            } catch (e: Exception) {
                throw Exception("Failed to decode Base64: ${e.message}")
            }
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
            return try {
                // Generate ECDSA Key Pair
                val keyPairGenerator = KeyPairGenerator.getInstance("EC")
                keyPairGenerator.initialize(256) // Using 256-bit ECC key
                val keyPair = keyPairGenerator.genKeyPair()

                val publicKey = keyPair.public.encoded
                val privateKey = keyPair.private.encoded

                // Encode keys as Base64
                val publicKeyBase64 = Base64.encodeToString(publicKey, Base64.DEFAULT)
                val privateKeyBase64 = Base64.encodeToString(privateKey, Base64.DEFAULT)

                // Create WritableMap
                val result: WritableMap = Arguments.createMap()
                result.putString("publicKey", publicKeyBase64)
                result.putString("privateKey", privateKeyBase64)

                result
            } catch (e: Exception) {
                e.printStackTrace()
                throw Exception("Failed to generate ECDSA key pair: ${e.localizedMessage}")
            }
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
            return try {
                // Decode the private key from Base64
                val privateKeyBytes = Base64.decode(key, Base64.DEFAULT)
                val keyFactory = KeyFactory.getInstance("EC")
                val privateKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)
                val privateKey = keyFactory.generatePrivate(privateKeySpec)

                // Initialize Signature Object
                val signature = Signature.getInstance("SHA256withECDSA")
                signature.initSign(privateKey)
                signature.update(data.toByteArray(Charsets.UTF_8))

                // Generate Signature
                val signedData = signature.sign()
                Base64.encodeToString(signedData, Base64.DEFAULT)
            } catch (e: Exception) {
                e.printStackTrace()
                throw Exception("Failed to sign data with ECDSA: ${e.localizedMessage}")
            }
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
            return try {
                // Decode the public key from Base64
                val publicKeyBytes = Base64.decode(key, Base64.DEFAULT)
                val keyFactory = KeyFactory.getInstance("EC")
                val publicKeySpec = X509EncodedKeySpec(publicKeyBytes)
                val publicKey = keyFactory.generatePublic(publicKeySpec)

                // Initialize the Signature object for verification
                val signature = Signature.getInstance("SHA256withECDSA")
                signature.initVerify(publicKey)
                signature.update(data.toByteArray(Charsets.UTF_8))

                // Decode the signature from Base64
                val signatureBytes = Base64.decode(signatureBase64, Base64.DEFAULT)

                // Verify the signature
                signature.verify(signatureBytes)
            } catch (e: Exception) {
                e.printStackTrace()
                throw Exception("Failed to verify ECDSA signature: ${e.localizedMessage}")
            }
        }

        companion object {
            const val NAME = "Encryption"
            private
            const val TAG = "AESEncryptionModule"
        }
    }