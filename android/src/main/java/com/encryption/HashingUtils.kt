import javax.crypto.Mac
import android.util.Base64
import kotlin.math.roundToInt
import java.security.*
import javax.crypto.spec.SecretKeySpec


object HashingUtils {

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
        fun hashSHA256(data: String): String {
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
        fun hashSHA512(input: String): String {
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
        fun hmacSHA256(data: String, key: String): String {
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
        fun generateRandomString(input: Double): String {
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
        fun base64Encode(input: String): String {
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
        fun base64Decode(input: String): String {
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
}