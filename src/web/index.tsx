// Web-specific implementation using web-encryption library
import * as WebEncryption from 'web-secure-encryption';

export const generateAESKey = WebEncryption.generateAESKey;
export const encryptAES = WebEncryption.encryptAES;
export const decryptAES = WebEncryption.decryptAES;
export const encryptAsyncAES = WebEncryption.encryptAsyncAES;
export const decryptAsyncAES = WebEncryption.decryptAsyncAES;
export const encryptRSA = WebEncryption.encryptRSA;
export const decryptRSA = WebEncryption.decryptRSA;
export const encryptAsyncRSA = WebEncryption.encryptAsyncRSA;
export const decryptAsyncRSA = WebEncryption.decryptAsyncRSA;
export const generateRSAKeyPair = WebEncryption.generateRSAKeyPair;
export const generateHMACKey = WebEncryption.generateHMACKey;
export const hmacSHA256 = WebEncryption.hmacSHA256;
export const hmacSHA512 = WebEncryption.hmacSHA512;
export const hashSHA256 = WebEncryption.hashSHA256;
export const hashSHA512 = WebEncryption.hashSHA512;
export const generateRandomString = WebEncryption.generateRandomString;
export const base64Encode = WebEncryption.base64Encode;
export const base64Decode = WebEncryption.base64Decode;
export const generateECDSAKeyPair = WebEncryption.generateECDSAKeyPair;
export const signDataECDSA = WebEncryption.signDataECDSA;
export const verifySignatureECDSA = WebEncryption.verifySignatureECDSA;
