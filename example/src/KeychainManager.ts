import * as Keychain from 'react-native-keychain';
import {
  generateAESKey,
  generateRSAKeyPair,
  generateECDSAKeyPair,
  generateHMACKey,
} from '../../src';

/**
 * Enum for allowed storage types in Keychain
 */
export enum STORAGE_TYPE {
  AES_GCM_NO_AUTH = 'KeystoreAESGCM_NoAuth',
  AES_GCM = 'KeystoreAESGCM',
  RSA = 'KeystoreRSAECB',
}

/**
 * KeychainManager: Handles secure storage and retrieval of encryption keys.
 */
export default class KeychainManager {
  private static AES_KEY_ALIAS = 'encryption_aes_key';
  private static RSA_KEY_ALIAS = 'encryption_rsa_key';
  private static ECDSA_KEY_ALIAS = 'encryption_ecdsa_key';
  private static HMAC_KEY_ALIAS = 'encryption_hmac_key';

  /**
   * Store a Key in Keychain with a specific storage type
   * @param keyAlias Key alias (AES, RSA, ECDSA, HMAC)
   * @param key The key data as a string
   * @param storageType Storage type from STORAGE_TYPE enum
   */
  static async storeKey(
    keyAlias: string,
    key: string,
    storageType: STORAGE_TYPE = STORAGE_TYPE.AES_GCM
  ): Promise<void> {
    try {
      await Keychain.setGenericPassword(keyAlias, key, {
        service: keyAlias,
        accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED,
      });
      console.log(
        `[Keychain] Key securely stored (${storageType}): ${keyAlias}`
      );
    } catch (error) {
      console.error(`[Keychain Error] Failed to store key: ${error}`);
    }
  }

  /**
   * Retrieve a Key from Keychain
   * @param keyAlias Key alias to retrieve
   * @returns The retrieved key or null if not found
   */
  static async retrieveKey(keyAlias: string): Promise<string | null> {
    try {
      const credentials = await Keychain.getGenericPassword({
        service: keyAlias,
      });
      if (credentials) {
        console.log(`[Keychain] Key securely retrieved: ${keyAlias}`);
        return credentials.password;
      }
      console.warn(`[Keychain] Key not found: ${keyAlias}`);
      return null;
    } catch (error) {
      console.error(`[Keychain Error] Failed to retrieve key: ${error}`);
      return null;
    }
  }

  /**
   * Delete a Key from Keychain
   * @param keyAlias Key alias to delete
   */
  static async deleteKey(keyAlias: string): Promise<void> {
    try {
      await Keychain.resetGenericPassword({ service: keyAlias });
      console.log(`[Keychain] Key successfully deleted: ${keyAlias}`);
    } catch (error) {
      console.error(`[Keychain Error] Failed to delete key: ${error}`);
    }
  }

  // -----------------------------------------------------------------------
  // ✅ AES Key Management
  // -----------------------------------------------------------------------

  /**
   * Generate and Store AES Key
   * @param keySize Key size in bits (128, 192, 256)
   * @param storageType Storage type from STORAGE_TYPE enum
   */
  static async generateAndStoreAESKey(
    keySize: number,
    storageType: STORAGE_TYPE = STORAGE_TYPE.AES_GCM
  ): Promise<string> {
    const aesKey = generateAESKey(keySize);
    await KeychainManager.storeKey(
      KeychainManager.AES_KEY_ALIAS,
      aesKey,
      storageType
    );
    return aesKey;
  }

  /**
   * Retrieve AES Key
   */
  static async getAESKey(): Promise<string | null> {
    return await KeychainManager.retrieveKey(KeychainManager.AES_KEY_ALIAS);
  }

  // -----------------------------------------------------------------------
  // ✅ RSA Key Management
  // -----------------------------------------------------------------------

  /**
   * Generate and Store RSA Key Pair
   * @param storageType Storage type from STORAGE_TYPE enum
   */
  static async generateAndStoreRSAKeyPair(
    storageType: STORAGE_TYPE = STORAGE_TYPE.RSA
  ): Promise<{ publicKey: string; privateKey: string }> {
    const { publicKey, privateKey } = generateRSAKeyPair();
    await KeychainManager.storeKey(
      KeychainManager.RSA_KEY_ALIAS,
      privateKey,
      storageType
    );
    return { publicKey, privateKey };
  }

  /**
   * Retrieve RSA Private Key
   */
  static async getRSAPrivateKey(): Promise<string | null> {
    return await KeychainManager.retrieveKey(KeychainManager.RSA_KEY_ALIAS);
  }

  // -----------------------------------------------------------------------
  // ✅ HMAC Key Management
  // -----------------------------------------------------------------------

  /**
   * Generate and Store HMAC Key
   * @param keySize Key size in bits (256, 512)
   * @param storageType Storage type from STORAGE_TYPE enum
   */
  static async generateAndStoreHMACKey(
    keySize: number,
    storageType: STORAGE_TYPE = STORAGE_TYPE.AES_GCM
  ): Promise<string> {
    const hmacKey = generateHMACKey(keySize);
    await KeychainManager.storeKey(
      KeychainManager.HMAC_KEY_ALIAS,
      hmacKey,
      storageType
    );
    return hmacKey;
  }

  /**
   * Retrieve HMAC Key
   */
  static async getHMACKey(): Promise<string | null> {
    return await KeychainManager.retrieveKey(KeychainManager.HMAC_KEY_ALIAS);
  }

  // -----------------------------------------------------------------------
  // ✅ ECDSA Key Management
  // -----------------------------------------------------------------------

  /**
   * Generate and Store ECDSA Key Pair
   * @param storageType Storage type from STORAGE_TYPE enum
   */
  static async generateAndStoreECDSAKeyPair(
    storageType: STORAGE_TYPE = STORAGE_TYPE.AES_GCM
  ): Promise<{ publicKey: string; privateKey: string }> {
    const { publicKey, privateKey } = generateECDSAKeyPair();
    await KeychainManager.storeKey(
      KeychainManager.ECDSA_KEY_ALIAS,
      privateKey,
      storageType
    );
    return { publicKey, privateKey };
  }

  /**
   * Retrieve ECDSA Private Key
   */
  static async getECDSAPrivateKey(): Promise<string | null> {
    return await KeychainManager.retrieveKey(KeychainManager.ECDSA_KEY_ALIAS);
  }
}
