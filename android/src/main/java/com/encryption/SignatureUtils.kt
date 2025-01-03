import com.facebook.react.bridge.Arguments

import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.Signature
import android.util.Base64
import javax.crypto.Cipher
import com.facebook.react.bridge.WritableMap
import javax.crypto.spec.IvParameterSpec
import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
object SignatureUtils {

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
         fun generateECDSAKeyPair(): WritableMap {
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
        fun signDataECDSA(data: String, key: String): String {
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
        fun verifySignatureECDSA(data: String, signatureBase64: String, key: String): Boolean {
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
}