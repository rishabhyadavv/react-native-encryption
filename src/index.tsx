import Encryption, { type keypair } from './NativeEncryption';

export function generateAESKey(input: number): string {
  return Encryption.generateAESKey(input);
}
export function encryptAES(data: string, key: string): string {
  return Encryption.encryptAES(data, key);
}
export function decryptAES(data: string, key: string): string {
  return Encryption.decryptAES(data, key);
}
export function encryptFile(
  inputPath: string,
  outputPath: string,
  key: string
): Promise<string> {
  return Encryption.encryptFile(inputPath, outputPath, key);
}
export function decryptFile(inputPath: string, key: string): Promise<string> {
  return Encryption.decryptFile(inputPath, key);
}

export function encryptAsyncAES(data: string, key: string): Promise<string> {
  return Encryption.encryptAsyncAES(data, key);
}
export function decryptAsyncAES(data: string, key: string): Promise<string> {
  return Encryption.decryptAsyncAES(data, key);
}

export function encryptAsyncRSA(data: string, key: string): Promise<string> {
  return Encryption.encryptAsyncRSA(data, key);
}
export function decryptAsyncRSA(data: string, key: string): Promise<string> {
  return Encryption.decryptAsyncRSA(data, key);
}
export function encryptRSA(data: string, key: string): string {
  return Encryption.encryptRSA(data, key);
}
export function decryptRSA(data: string, key: string): string {
  return Encryption.decryptRSA(data, key);
}
export function generateHMACKey(keySize: number): string {
  return Encryption.generateHMACKey(keySize);
}
export function hmacSHA256(data: string, key: string): string {
  return Encryption.hmacSHA256(data, key);
}
export function hmacSHA512(data: string, key: string): string {
  return Encryption.hmacSHA512(data, key);
}
export function hashSHA512(input: string): string {
  return Encryption.hashSHA512(input);
}
export function hashSHA256(input: string): string {
  return Encryption.hashSHA256(input);
}
export function base64Encode(input: string): string {
  return Encryption.base64Encode(input);
}
export function base64Decode(input: string): string {
  return Encryption.base64Decode(input);
}
export function generateRandomString(input: number): string {
  return Encryption.generateRandomString(input);
}

export function generateRSAKeyPair(): keypair {
  return Encryption.generateRSAKeyPair();
}

export function getPublicRSAkey(privateRSAkey: string): string {
  return Encryption.getPublicRSAkey(privateRSAkey);
}

export function generateECDSAKeyPair(): keypair {
  return Encryption.generateECDSAKeyPair();
}

export function getPublicECDSAKey(privateECDAkey: string): string {
  return Encryption.getPublicECDSAKey(privateECDAkey);
}

export function signDataECDSA(data: string, key: string): string {
  return Encryption.signDataECDSA(data, key);
}

export function verifySignatureECDSA(
  data: string,
  signatureBase64: string,
  key: string
): boolean {
  return Encryption.verifySignatureECDSA(data, signatureBase64, key);
}
