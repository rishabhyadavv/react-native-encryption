package com.encryption

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.annotations.ReactModule
import java.security.SecureRandom

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import android.util.Base64
import android.util.Log
import kotlin.math.roundToInt

@ReactModule(name = EncryptionModule.NAME)
class EncryptionModule(reactContext: ReactApplicationContext) :
  NativeEncryptionSpec(reactContext) {

  override fun getName(): String {
    return NAME
  }
  
 // -----------------------------------------
    // 🔒 AES Encryption
    // -----------------------------------------
    @Throws(IllegalArgumentException::class, Exception::class)
    override fun encryptAES(data: String, key: String): String {
        if (data.isEmpty() || key.isEmpty()) {
            throw IllegalArgumentException("Data or key cannot be empty.")
        }

        if (key.toByteArray().size != 16) {
            throw IllegalArgumentException("AES Key must be 16 bytes (128 bits).")
        }

        val iv = ByteArray(16)
        SecureRandom().nextBytes(iv)
        val ivSpec = IvParameterSpec(iv)

        val secretKey = SecretKeySpec(key.toByteArray(), "AES")
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)

        val encryptedData = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
        val combined = iv + encryptedData

        return Base64.encodeToString(combined, Base64.DEFAULT)
    }

    @Throws(IllegalArgumentException::class, Exception::class)
    override fun decryptAES(data: String, key: String): String {
        if (data.isEmpty() || key.isEmpty()) {
            throw IllegalArgumentException("Data or key cannot be empty.")
        }

        if (key.toByteArray().size != 16) {
            throw IllegalArgumentException("AES Key must be 16 bytes (128 bits).")
        }

        val decodedData = Base64.decode(data, Base64.DEFAULT)
        val iv = decodedData.copyOfRange(0, 16)
        val encryptedBytes = decodedData.copyOfRange(16, decodedData.size)
        val ivSpec = IvParameterSpec(iv)

        val secretKey = SecretKeySpec(key.toByteArray(), "AES")
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)

        return String(cipher.doFinal(encryptedBytes), Charsets.UTF_8)
    }

    // -----------------------------------------
    // 🔑 RSA Encryption
    // -----------------------------------------
    @Throws(IllegalArgumentException::class, Exception::class)
    override fun encryptRSA(data: String, publicKey: String): String {
        if (data.isEmpty() || publicKey.isEmpty()) {
            throw IllegalArgumentException("Invalid data or public key.")
        }

        val publicKeyBytes = Base64.decode(publicKey, Base64.DEFAULT)
        val keySpec = X509EncodedKeySpec(publicKeyBytes)
        val publicKeyObj = KeyFactory.getInstance("RSA").generatePublic(keySpec)

        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKeyObj)
        val encryptedBytes = cipher.doFinal(data.toByteArray(Charsets.UTF_8))

        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    @Throws(IllegalArgumentException::class, Exception::class)
    override fun decryptRSA(data: String, privateKey: String): String {
        if (data.isEmpty() || privateKey.isEmpty()) {
            throw IllegalArgumentException("Invalid data or private key.")
        }

        val privateKeyBytes = Base64.decode(privateKey, Base64.DEFAULT)
        val keySpec = PKCS8EncodedKeySpec(privateKeyBytes)
        val privateKeyObj = KeyFactory.getInstance("RSA").generatePrivate(keySpec)

        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKeyObj)
        val decryptedBytes = cipher.doFinal(Base64.decode(data, Base64.DEFAULT))

        return String(decryptedBytes, Charsets.UTF_8)
    }

    // -----------------------------------------
    // 🛡️ SHA Hashing
    // -----------------------------------------
    @Throws(Exception::class)
    override fun hashSHA256(data: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(data.toByteArray())
        return hash.joinToString("") { "%02x".format(it) }
    }

    @Throws(Exception::class)
    override fun hashSHA512(input: String): String {
        if (input.isEmpty()) {
            throw IllegalArgumentException("Input string cannot be empty for SHA-512 hashing")
        }

        val bytes = input.toByteArray(Charsets.UTF_8)
        val md = MessageDigest.getInstance("SHA-512")
        val digest = md.digest(bytes)

        // Convert to hex string
        return digest.joinToString("") { "%02x".format(it) }
    }

    // -----------------------------------------
    // 📝 HMAC-SHA256
    // -----------------------------------------
    @Throws(Exception::class)
    override fun hmacSHA256(data: String, key: String): String {
        val secretKey = SecretKeySpec(key.toByteArray(), "HmacSHA256")
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(secretKey)
        val hash = mac.doFinal(data.toByteArray())
        return hash.joinToString("") { "%02x".format(it) }
    }

    // -----------------------------------------
    // 🎲 Random String Generation
    // -----------------------------------------
     @Throws(Exception::class)
    override fun generateRandomString(input: Double): String {
        val length = input.roundToInt()
        if (length <= 0) {
            throw IllegalArgumentException("Length must be a positive number.")
        }

        val charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        val random = SecureRandom()
        return (1..length)
            .map { charset[random.nextInt(charset.length)] }
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

  companion object {
    const val NAME = "Encryption"
    private const val TAG = "AESEncryptionModule"
  }
}
