package com.encryption

import org.junit.Assert.*
import org.junit.Test
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPublicKeySpec
import java.security.spec.ECFieldFp
import java.security.spec.ECPoint
import java.util.Base64

/**
 * Pure JVM unit tests for ECDSA public key derivation from private key.
 *
 * These tests verify that the EC point multiplication algorithm correctly
 * derives a public key from a private key. This is the same algorithm
 * used in SignatureUtils.getPublicECDSAKey().
 *
 * These tests do NOT require Android SDK and can run on any JVM.
 */
class ECDSAPublicKeyDerivationTest {

    /**
     * Performs elliptic curve point multiplication using the double-and-add algorithm.
     * This is a copy of the algorithm in SignatureUtils for testing purposes.
     */
    private fun ecPointMultiply(
        point: ECPoint,
        k: BigInteger,
        p: BigInteger,
        a: BigInteger
    ): ECPoint {
        var result = ECPoint.POINT_INFINITY
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

    private fun ecPointAdd(
        p1: ECPoint,
        p2: ECPoint,
        p: BigInteger,
        a: BigInteger
    ): ECPoint {
        if (p1 == ECPoint.POINT_INFINITY) return p2
        if (p2 == ECPoint.POINT_INFINITY) return p1

        val x1 = p1.affineX
        val y1 = p1.affineY
        val x2 = p2.affineX
        val y2 = p2.affineY

        if (x1 == x2 && y1 == y2) {
            return ecPointDouble(p1, p, a)
        }

        if (x1 == x2) {
            return ECPoint.POINT_INFINITY
        }

        val deltaY = y2.subtract(y1).mod(p)
        val deltaX = x2.subtract(x1).mod(p)
        val lambda = deltaY.multiply(deltaX.modInverse(p)).mod(p)

        val x3 = lambda.multiply(lambda).subtract(x1).subtract(x2).mod(p)
        val y3 = lambda.multiply(x1.subtract(x3)).subtract(y1).mod(p)

        return ECPoint(x3, y3)
    }

    private fun ecPointDouble(
        point: ECPoint,
        p: BigInteger,
        a: BigInteger
    ): ECPoint {
        if (point == ECPoint.POINT_INFINITY) {
            return point
        }

        val x = point.affineX
        val y = point.affineY

        if (y == BigInteger.ZERO) {
            return ECPoint.POINT_INFINITY
        }

        val numerator = x.multiply(x).multiply(BigInteger.valueOf(3)).add(a).mod(p)
        val denominator = y.multiply(BigInteger.valueOf(2)).mod(p)
        val lambda = numerator.multiply(denominator.modInverse(p)).mod(p)

        val x3 = lambda.multiply(lambda).subtract(x.multiply(BigInteger.valueOf(2))).mod(p)
        val y3 = lambda.multiply(x.subtract(x3)).subtract(y).mod(p)

        return ECPoint(x3, y3)
    }

    /**
     * Derives a public key from a private key using EC point multiplication.
     */
    private fun derivePublicKey(privateKey: ECPrivateKey): ECPublicKey {
        val ecParameterSpec = privateKey.params
        val d = privateKey.s
        val g = ecParameterSpec.generator
        val p = (ecParameterSpec.curve.field as ECFieldFp).p
        val a = ecParameterSpec.curve.a

        val q = ecPointMultiply(g, d, p, a)

        val publicKeySpec = ECPublicKeySpec(q, ecParameterSpec)
        val keyFactory = KeyFactory.getInstance("EC")
        return keyFactory.generatePublic(publicKeySpec) as ECPublicKey
    }

    /**
     * Test that public key derivation is deterministic.
     */
    @Test
    fun testPublicKeyDerivation_isDeterministic() {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(256)
        val keyPair = keyPairGenerator.genKeyPair()
        val privateKey = keyPair.private as ECPrivateKey

        val derivedPublicKey1 = derivePublicKey(privateKey)
        val derivedPublicKey2 = derivePublicKey(privateKey)
        val derivedPublicKey3 = derivePublicKey(privateKey)

        assertArrayEquals(
            "Public key derivation should be deterministic",
            derivedPublicKey1.encoded,
            derivedPublicKey2.encoded
        )
        assertArrayEquals(
            "Public key derivation should be deterministic",
            derivedPublicKey2.encoded,
            derivedPublicKey3.encoded
        )
    }

    /**
     * Test that the derived public key matches the originally generated public key.
     */
    @Test
    fun testDerivedPublicKey_matchesOriginal() {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(256)
        val keyPair = keyPairGenerator.genKeyPair()

        val originalPublicKey = keyPair.public as ECPublicKey
        val privateKey = keyPair.private as ECPrivateKey

        val derivedPublicKey = derivePublicKey(privateKey)

        assertArrayEquals(
            "Derived public key should match the originally generated public key",
            originalPublicKey.encoded,
            derivedPublicKey.encoded
        )
    }

    /**
     * Test that signatures can be verified using the derived public key.
     */
    @Test
    fun testDerivedPublicKey_canVerifySignatures() {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(256)
        val keyPair = keyPairGenerator.genKeyPair()
        val privateKey = keyPair.private as ECPrivateKey

        val derivedPublicKey = derivePublicKey(privateKey)

        // Sign some data
        val testData = "Hello, ECDSA!".toByteArray()
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        signature.update(testData)
        val signatureBytes = signature.sign()

        // Verify using derived public key
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(derivedPublicKey)
        verifier.update(testData)
        val isValid = verifier.verify(signatureBytes)

        assertTrue("Signature should be valid when verified with the derived public key", isValid)
    }

    /**
     * Test that different private keys produce different public keys.
     */
    @Test
    fun testDifferentPrivateKeys_produceDifferentPublicKeys() {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(256)

        val keyPair1 = keyPairGenerator.genKeyPair()
        val keyPair2 = keyPairGenerator.genKeyPair()

        val privateKey1 = keyPair1.private as ECPrivateKey
        val privateKey2 = keyPair2.private as ECPrivateKey

        val derivedPublicKey1 = derivePublicKey(privateKey1)
        val derivedPublicKey2 = derivePublicKey(privateKey2)

        assertFalse(
            "Different private keys should produce different public keys",
            derivedPublicKey1.encoded.contentEquals(derivedPublicKey2.encoded)
        )
    }

    /**
     * Test that a signature cannot be verified with the wrong public key.
     */
    @Test
    fun testSignatureVerification_failsWithWrongPublicKey() {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(256)

        val keyPair1 = keyPairGenerator.genKeyPair()
        val keyPair2 = keyPairGenerator.genKeyPair()

        val privateKey1 = keyPair1.private as ECPrivateKey
        val privateKey2 = keyPair2.private as ECPrivateKey

        val derivedPublicKey2 = derivePublicKey(privateKey2)

        // Sign with first private key
        val testData = "Test message".toByteArray()
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey1)
        signature.update(testData)
        val signatureBytes = signature.sign()

        // Try to verify with second public key (should fail)
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(derivedPublicKey2)
        verifier.update(testData)
        val isValid = verifier.verify(signatureBytes)

        assertFalse("Signature should not verify with wrong public key", isValid)
    }

    /**
     * Test multiple key pairs to ensure consistency.
     */
    @Test
    fun testMultipleKeyPairs_consistentDerivation() {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(256)

        repeat(10) { iteration ->
            val keyPair = keyPairGenerator.genKeyPair()
            val originalPublicKey = keyPair.public as ECPublicKey
            val privateKey = keyPair.private as ECPrivateKey

            val derivedPublicKey = derivePublicKey(privateKey)

            assertArrayEquals(
                "Derived public key should match original for iteration $iteration",
                originalPublicKey.encoded,
                derivedPublicKey.encoded
            )

            // Also verify signature works
            val testData = "Test data for iteration $iteration".toByteArray()
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(privateKey)
            signature.update(testData)
            val signatureBytes = signature.sign()

            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(derivedPublicKey)
            verifier.update(testData)
            val isValid = verifier.verify(signatureBytes)

            assertTrue("Signature verification should pass for iteration $iteration", isValid)
        }
    }

    /**
     * Test with Base64 encoding/decoding (simulates the full SignatureUtils flow).
     */
    @Test
    fun testWithBase64EncodingDecoding() {
        val keyPairGenerator = KeyPairGenerator.getInstance("EC")
        keyPairGenerator.initialize(256)
        val keyPair = keyPairGenerator.genKeyPair()

        val originalPublicKey = keyPair.public as ECPublicKey
        val privateKey = keyPair.private as ECPrivateKey

        // Simulate encoding and decoding like SignatureUtils does
        val privateKeyBase64 = Base64.getEncoder().encodeToString(privateKey.encoded)
        val originalPublicKeyBase64 = Base64.getEncoder().encodeToString(originalPublicKey.encoded)

        // Decode private key
        val decodedPrivateKeyBytes = Base64.getDecoder().decode(privateKeyBase64)
        val keyFactory = KeyFactory.getInstance("EC")
        val privateKeySpec = java.security.spec.PKCS8EncodedKeySpec(decodedPrivateKeyBytes)
        val reconstructedPrivateKey = keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey

        // Derive public key
        val derivedPublicKey = derivePublicKey(reconstructedPrivateKey)
        val derivedPublicKeyBase64 = Base64.getEncoder().encodeToString(derivedPublicKey.encoded)

        assertEquals(
            "Base64-encoded derived public key should match original",
            originalPublicKeyBase64,
            derivedPublicKeyBase64
        )
    }
}
