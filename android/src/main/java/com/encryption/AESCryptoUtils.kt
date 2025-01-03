// AESCryptoUtils.kt
import android.util.Base64
import java.nio.charset.Charset
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

object AESCryptoUtils {

    private const val AES_MODE = "AES/GCM/NoPadding"
    private const val IV_SIZE = 12
    private const val TAG_LENGTH = 128

    /**
         * Generates an AES encryption key of specified size.
         *
         * @param keySize The size of the AES key in bits (128, 192, or 256).
         * @return A Base64-encoded AES key.
         * @throws IllegalArgumentException if the key size is invalid.
         * @throws Exception if key generation fails.
         */
        @Throws(IllegalArgumentException::class)
        fun generateAESKey(keySize: Double): String {
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

    /**
     * Encrypts the given plaintext using AES-GCM.
     *
     * @param data Plaintext string to encrypt.
     * @param key AES key in Base64 format.
     * @return Encrypted string in Base64 format with IV prepended.
     */
    @Throws(IllegalArgumentException::class, Exception::class)
    fun encrypt(data: String, key: String): String {
        if (data.isEmpty() || key.isEmpty()) {
            throw IllegalArgumentException("Data or key cannot be empty.")
        }

          val keyBytes =
                try {
                    Base64.decode(key, Base64.DEFAULT)
                } catch (e: Exception) {
                    throw IllegalArgumentException("Invalid AES key format: ${e.localizedMessage}")
                }
        if (keyBytes.size !in listOf(16, 24, 32)) {
            throw IllegalArgumentException("Invalid AES key size. Must be 16, 24, or 32 bytes (128, 192, or 256 bits).")
        }

        // Generate Initialization Vector (IV)
        val iv = ByteArray(IV_SIZE)
        SecureRandom().nextBytes(iv)
        val ivSpec = GCMParameterSpec(TAG_LENGTH, iv)

        // Initialize Cipher
        val secretKey = SecretKeySpec(keyBytes, "AES")
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)

        // Encrypt data
        val encryptedData = cipher.doFinal(data.toByteArray(Charsets.UTF_8))

        // Combine IV and Encrypted Data
        val combined = iv + encryptedData

        // Encode as Base64
        return Base64.encodeToString(combined, Base64.DEFAULT)
    }

    /**
     * Decrypts the given AES-GCM encrypted string.
     *
     * @param data Encrypted data in Base64 format (with IV prepended).
     * @param key AES key in Base64 format.
     * @return Decrypted plaintext string.
     */
    @Throws(IllegalArgumentException::class, Exception::class)
    fun decrypt(data: String, key: String): String {
        if (data.isEmpty() || key.isEmpty()) {
            throw IllegalArgumentException("Data or key cannot be empty.")
        }

        val keyBytes = Base64.decode(key, Base64.DEFAULT)
        if (keyBytes.size !in listOf(16, 24, 32)) {
            throw IllegalArgumentException("Invalid AES key size. Must be 16, 24, or 32 bytes (128, 192, or 256 bits).")
        }

        val decodedData = Base64.decode(data, Base64.DEFAULT)
        if (decodedData.size < IV_SIZE) {
            throw IllegalArgumentException("Invalid encrypted data. Data too short to contain IV.")
        }

        // Extract IV and Encrypted Data
        val iv = decodedData.copyOfRange(0, IV_SIZE)
        val encryptedBytes = decodedData.copyOfRange(IV_SIZE, decodedData.size)
        val ivSpec = GCMParameterSpec(TAG_LENGTH, iv)

        // Initialize Cipher
        val secretKey = SecretKeySpec(keyBytes, "AES")
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)

        // Decrypt data
        val decryptedData = cipher.doFinal(encryptedBytes)
        return String(decryptedData, Charsets.UTF_8)
    }

/**
 * Encrypt ByteArray directly (e.g., for file encryption).
 */
@Throws(Exception::class)
fun encryptBytes(data: ByteArray, key: String): ByteArray {
    val keyBytes = Base64.decode(key, Base64.DEFAULT)
    val secretKey = SecretKeySpec(keyBytes, "AES")
    val iv = ByteArray(12)
    SecureRandom().nextBytes(iv)

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))

    val encryptedData = cipher.doFinal(data)
    return iv + encryptedData
}

/**
 * Decrypt ByteArray directly (e.g., for file decryption).
 */
@Throws(Exception::class)
fun decryptBytes(data: ByteArray, key: String): ByteArray {
    val keyBytes = Base64.decode(key, Base64.DEFAULT)
    val secretKey = SecretKeySpec(keyBytes, "AES")

    val iv = data.copyOfRange(0, 12)
    val encryptedData = data.copyOfRange(12, data.size)

    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))

    return cipher.doFinal(encryptedData)
}
}
