import android.util.Base64
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.WritableMap
import java.security.*
import java.security.spec.*
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.math.BigInteger

/**
 * SignatureUtils: Utility class for ECDSA Key Pair Management, Signing, and Verification.
 */
object SignatureUtils {

    /**
     * Generates an ECDSA (Elliptic Curve Digital Signature Algorithm) key pair.
     * Encodes both the public and private keys into Base64 strings and returns them as a WritableMap.
     *
     * @return WritableMap containing:
     *   - `publicKey`: Base64-encoded ECDSA public key.
     *   - `privateKey`: Base64-encoded ECDSA private key.
     */
    @Throws(Exception::class)
    fun generateECDSAKeyPair(): WritableMap {
        return try {
            val keyPairGenerator = KeyPairGenerator.getInstance("EC")
            keyPairGenerator.initialize(256) // Using 256-bit ECC key
            val keyPair = keyPairGenerator.genKeyPair()

            val publicKeyBase64 = Base64.encodeToString(keyPair.public.encoded, Base64.DEFAULT)
            val privateKeyBase64 = Base64.encodeToString(keyPair.private.encoded, Base64.DEFAULT)

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
     * Extracts the public key from a given ECDSA private key.
     *
     * @param privateKeyBase64 Base64-encoded private key.
     * @return Base64-encoded public key derived from the private key.
     */
    @Throws(Exception::class)
   fun getPublicECDSAKey(privateKeyBase64: String): String {
    return try {
        // Decode the Base64 private key
        val privateKeyBytes = Base64.decode(privateKeyBase64, Base64.DEFAULT)
        val keyFactory = KeyFactory.getInstance("EC")

        // Generate the private key
        val privateKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)
        val privateKey = keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey

        // Generate the public key from the private key parameters
        val ecParameterSpec = privateKey.params
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(ecParameterSpec)
        val keyPair = keyPairGenerator.genKeyPair()

        val publicKey = keyPair.public as ECPublicKey
        val publicKeyBytes = publicKey.encoded
        val publicKeyBase64 = Base64.encodeToString(publicKeyBytes, Base64.DEFAULT)

        // Return both public and private keys
        return publicKeyBase64
    } catch (e: Exception) {
        e.printStackTrace()
        throw Exception("Failed to extract public key from private key: ${e.localizedMessage}")
    }
}

    /**
     * Signs data using an ECDSA private key.
     *
     * @param data The plaintext data to sign.
     * @param privateKeyBase64 The Base64-encoded ECDSA private key.
     * @return Base64-encoded digital signature.
     */
    @Throws(Exception::class)
    fun signDataECDSA(data: String, privateKeyBase64: String): String {
        return try {
            val privateKeyBytes = Base64.decode(privateKeyBase64, Base64.DEFAULT)
            val keyFactory = KeyFactory.getInstance("EC")
            val privateKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)
            val privateKey = keyFactory.generatePrivate(privateKeySpec)

            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(privateKey)
            signature.update(data.toByteArray(Charsets.UTF_8))

            val signedData = signature.sign()
            Base64.encodeToString(signedData, Base64.DEFAULT)
        } catch (e: Exception) {
            e.printStackTrace()
            throw Exception("Failed to sign data with ECDSA: ${e.localizedMessage}")
        }
    }

    /**
     * Verifies an ECDSA signature using the provided public key.
     *
     * @param data The original plaintext data.
     * @param signatureBase64 The Base64-encoded digital signature.
     * @param publicKeyBase64 The Base64-encoded ECDSA public key.
     * @return `true` if the signature is valid, `false` otherwise.
     */
    @Throws(Exception::class)
    fun verifySignatureECDSA(data: String, signatureBase64: String, publicKeyBase64: String): Boolean {
        return try {
            val publicKeyBytes = Base64.decode(publicKeyBase64, Base64.DEFAULT)
            val keyFactory = KeyFactory.getInstance("EC")
            val publicKeySpec = X509EncodedKeySpec(publicKeyBytes)
            val publicKey = keyFactory.generatePublic(publicKeySpec)

            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initVerify(publicKey)
            signature.update(data.toByteArray(Charsets.UTF_8))

            val signatureBytes = Base64.decode(signatureBase64, Base64.DEFAULT)
            signature.verify(signatureBytes)
        } catch (e: Exception) {
            e.printStackTrace()
            throw Exception("Failed to verify ECDSA signature: ${e.localizedMessage}")
        }
    }
}
