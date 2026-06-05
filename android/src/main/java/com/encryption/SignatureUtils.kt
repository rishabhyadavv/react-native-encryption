import android.util.Base64
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.WritableMap
import java.security.*
import java.security.spec.*
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.math.BigInteger

/**
 * SignatureUtils: Utility class for ECDSA and RSA Key Pair Management, Signing, and Verification.
 */
object SignatureUtils {

    /**
     * Signs data using an RSA private key with SHA256withRSA.
     *
     * @param data The plaintext data to sign.
     * @param privateKeyBase64 The Base64-encoded RSA private key (PKCS#8).
     * @return Base64-encoded digital signature.
     */
    @Throws(Exception::class)
    fun signDataRSA(data: String, privateKeyBase64: String): String {
        return try {
            val privateKeyBytes = Base64.decode(privateKeyBase64, Base64.DEFAULT)
            val keyFactory = KeyFactory.getInstance("RSA")
            val privateKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)
            val privateKey = keyFactory.generatePrivate(privateKeySpec)

            val signature = Signature.getInstance("SHA256withRSA")
            signature.initSign(privateKey)
            signature.update(data.toByteArray(Charsets.UTF_8))

            val signedData = signature.sign()
            Base64.encodeToString(signedData, Base64.NO_WRAP)
        } catch (e: Exception) {
            e.printStackTrace()
            throw Exception("Failed to sign data with RSA: ${e.localizedMessage}")
        }
    }

    /**
     * Verifies an RSA signature using the provided public key with SHA256withRSA.
     *
     * @param data The original plaintext data.
     * @param signatureBase64 The Base64-encoded digital signature.
     * @param publicKeyBase64 The Base64-encoded RSA public key (X.509).
     * @return `true` if the signature is valid, `false` otherwise.
     */
    @Throws(Exception::class)
    fun verifySignatureRSA(data: String, signatureBase64: String, publicKeyBase64: String): Boolean {
        return try {
            val publicKeyBytes = Base64.decode(publicKeyBase64, Base64.DEFAULT)
            val keyFactory = KeyFactory.getInstance("RSA")
            val publicKeySpec = X509EncodedKeySpec(publicKeyBytes)
            val publicKey = keyFactory.generatePublic(publicKeySpec)

            val signature = Signature.getInstance("SHA256withRSA")
            signature.initVerify(publicKey)
            signature.update(data.toByteArray(Charsets.UTF_8))

            val signatureBytes = Base64.decode(signatureBase64, Base64.DEFAULT)
            signature.verify(signatureBytes)
        } catch (e: Exception) {
            e.printStackTrace()
            throw Exception("Failed to verify RSA signature: ${e.localizedMessage}")
        }
    }


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

            // Reconstruct the private key
            val privateKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)
            val privateKey = keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey

            // Derive the public key from the private key using EC point multiplication
            // Public key Q = d * G, where d is the private scalar and G is the generator point
            val ecParameterSpec = privateKey.params
            val d = privateKey.s  // The private key scalar
            val g = ecParameterSpec.generator  // The generator point G
            val p = (ecParameterSpec.curve.field as java.security.spec.ECFieldFp).p
            val a = ecParameterSpec.curve.a

            // Calculate Q = d * G using double-and-add algorithm
            val q = ecPointMultiply(g, d, p, a)

            // Create the public key from the calculated point
            val publicKeySpec = ECPublicKeySpec(q, ecParameterSpec)
            val publicKey = keyFactory.generatePublic(publicKeySpec) as ECPublicKey

            Base64.encodeToString(publicKey.encoded, Base64.DEFAULT)
        } catch (e: Exception) {
            e.printStackTrace()
            throw Exception("Failed to extract public key from private key: ${e.localizedMessage}")
        }
    }

    /**
     * Performs elliptic curve point multiplication using the double-and-add algorithm.
     * Calculates result = k * point on the elliptic curve.
     */
    private fun ecPointMultiply(
        point: java.security.spec.ECPoint,
        k: BigInteger,
        p: BigInteger,
        a: BigInteger
    ): java.security.spec.ECPoint {
        var result = java.security.spec.ECPoint.POINT_INFINITY
        var addend = point
        var scalar = k

        while (scalar != BigInteger.ZERO) {
            if (scalar.testBit(0)) {
                result = ecPointAdd(result, addend, p, a)
            }
            addend = ecPointDouble(addend, p, a)
            scalar = scalar.shiftRight(1)
        }

        return result
    }

    /**
     * Adds two points on the elliptic curve.
     */
    private fun ecPointAdd(
        p1: java.security.spec.ECPoint,
        p2: java.security.spec.ECPoint,
        p: BigInteger,
        a: BigInteger
    ): java.security.spec.ECPoint {
        if (p1 == java.security.spec.ECPoint.POINT_INFINITY) return p2
        if (p2 == java.security.spec.ECPoint.POINT_INFINITY) return p1

        val x1 = p1.affineX
        val y1 = p1.affineY
        val x2 = p2.affineX
        val y2 = p2.affineY

        // Check if points are the same (use point doubling)
        if (x1 == x2 && y1 == y2) {
            return ecPointDouble(p1, p, a)
        }

        // Check if points are inverses (result is point at infinity)
        if (x1 == x2) {
            return java.security.spec.ECPoint.POINT_INFINITY
        }

        // Point addition: lambda = (y2 - y1) / (x2 - x1) mod p
        val deltaY = y2.subtract(y1).mod(p)
        val deltaX = x2.subtract(x1).mod(p)
        val lambda = deltaY.multiply(deltaX.modInverse(p)).mod(p)

        // x3 = lambda^2 - x1 - x2 mod p
        val x3 = lambda.multiply(lambda).subtract(x1).subtract(x2).mod(p)

        // y3 = lambda * (x1 - x3) - y1 mod p
        val y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(p)

        return java.security.spec.ECPoint(x3, y3)
    }

    /**
     * Doubles a point on the elliptic curve.
     */
    private fun ecPointDouble(
        point: java.security.spec.ECPoint,
        p: BigInteger,
        a: BigInteger
    ): java.security.spec.ECPoint {
        if (point == java.security.spec.ECPoint.POINT_INFINITY) {
            return point
        }

        val x = point.affineX
        val y = point.affineY

        // Check for point at infinity (y = 0)
        if (y == BigInteger.ZERO) {
            return java.security.spec.ECPoint.POINT_INFINITY
        }

        // Point doubling: lambda = (3 * x^2 + a) / (2 * y) mod p
        val numerator = x.multiply(x).multiply(BigInteger.valueOf(3)).add(a).mod(p)
        val denominator = y.multiply(BigInteger.valueOf(2)).mod(p)
        val lambda = numerator.multiply(denominator.modInverse(p)).mod(p)

        // x3 = lambda^2 - 2*x mod p
        val x3 = lambda.multiply(lambda).subtract(x.multiply(BigInteger.valueOf(2))).mod(p)

        // y3 = lambda * (x - x3) - y mod p
        val y3 = lambda.multiply(x.subtract(x3)).subtract(y).mod(p)

        return java.security.spec.ECPoint(x3, y3)
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
