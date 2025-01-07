import { Platform } from 'react-native';

let Encryption: any;

if (Platform.OS === 'web') {
  // Use web-encryption for web
  Encryption = require('./web/index');
} else {
  // Use native TurboModules for mobile
  Encryption = require('./native/index');
}

// Export all encryption methods
export const {
  generateAESKey,
  encryptAES,
  decryptAES,
  encryptRSA,
  decryptRSA,
  generateRSAKeyPair,
  generateHMACKey,
  hmacSHA256,
  hmacSHA512,
  hashSHA256,
  hashSHA512,
  generateRandomString,
  base64Encode,
  base64Decode,
  generateECDSAKeyPair,
  signDataECDSA,
  verifySignatureECDSA,
  encryptAsyncAES,
  decryptAsyncAES,
  encryptAsyncRSA,
  decryptAsyncRSA,
  encryptFile,
  decryptFile,
  getPublicRSAkey,
  getPublicECDSAKey,
} = Encryption;
