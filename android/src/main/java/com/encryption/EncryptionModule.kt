package com.encryption

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.annotations.ReactModule
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
import android.util.Base64
import android.util.Log

@ReactModule(name = EncryptionModule.NAME)
class EncryptionModule(reactContext: ReactApplicationContext) :
  NativeEncryptionSpec(reactContext) {

  override fun getName(): String {
    return NAME
  }
  
  override fun encrypt(data: String, key: String): String {
    return try {
        Log.d(TAG, "Starting encryption...")

        // Validate key length
        if (key.toByteArray().size != 16) {
            val errorMessage = "Error: Key must be 16 bytes (128 bits) long."
            Log.e(TAG, "Encryption failed: $errorMessage")
            return errorMessage
        }

        // Generate a random IV
        val iv = ByteArray(16)
        SecureRandom().nextBytes(iv)
        val ivSpec = IvParameterSpec(iv)

        val secretKey = SecretKeySpec(key.toByteArray(), "AES")
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)
        val encryptedData = cipher.doFinal(data.toByteArray())

        // Combine IV and encrypted data
        val combined = iv + encryptedData
        val base64 = Base64.encodeToString(combined, Base64.DEFAULT)

        Log.d(TAG, "Encryption successful. Encrypted data (Base64): $base64")
        base64 // Return the encrypted data
    } catch (e: Exception) {
        val errorMessage = "Error: Encryption failed - ${e.message}"
        Log.e(TAG, errorMessage, e)
        errorMessage // Return the error message
    }
}


  override fun decrypt(encryptedData: String, key: String): String {
    return try {
        Log.d(TAG, "Starting decryption...")

        // Validate key length
        if (key.toByteArray().size != 16) {
            val errorMessage = "Error: Key must be 16 bytes (128 bits) long."
            Log.e(TAG, "Decryption failed: $errorMessage")
            return errorMessage
        }

        val decodedData = Base64.decode(encryptedData, Base64.DEFAULT)

        // Extract IV and encrypted data
        val iv = decodedData.copyOfRange(0, 16)
        val encryptedBytes = decodedData.copyOfRange(16, decodedData.size)
        val ivSpec = IvParameterSpec(iv)

        val secretKey = SecretKeySpec(key.toByteArray(), "AES")
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
        val decryptedData = cipher.doFinal(encryptedBytes)

        val result = String(decryptedData)
        Log.d(TAG, "Decryption successful. Decrypted data: $result")
        result // Return the decrypted data
    } catch (e: Exception) {
        val errorMessage = "Error: Decryption failed - ${e.message}"
        Log.e(TAG, errorMessage, e)
        errorMessage // Return the error message
    }
}

  companion object {
    const val NAME = "Encryption"
    private const val TAG = "AESEncryptionModule"
  }
}
