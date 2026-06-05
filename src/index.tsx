import { Platform } from 'react-native';

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

type EncryptionModule = {
  generateAESKey(input: number): string;
  encryptAES(data: string, key: string): string;
  decryptAES(data: string, key: string): string;
  encryptRSA(data: string, key: string): string;
  decryptRSA(data: string, key: string): string;
  generateRSAKeyPair(): KeyPair;
  signDataRSA(data: string, key: string): string;
  verifySignatureRSA(
    data: string,
    signatureBase64: string,
    key: string
  ): boolean;
  generateHMACKey(keySize: number): string;
  hmacSHA256(data: string, key: string): string;
  hmacSHA512(data: string, key: string): string;
  hashSHA256(input: string): string;
  hashSHA512(input: string): string;
  generateRandomString(input: number): string;
  base64Encode(input: string): string;
  base64Decode(input: string): string;
  generateECDSAKeyPair(): KeyPair;
  signDataECDSA(data: string, key: string): string;
  verifySignatureECDSA(
    data: string,
    signatureBase64: string,
    key: string
  ): boolean;
  encryptAsyncAES(data: string, key: string): Promise<string>;
  decryptAsyncAES(data: string, key: string): Promise<string>;
  encryptAsyncRSA(data: string, key: string): Promise<string>;
  decryptAsyncRSA(data: string, key: string): Promise<string>;
  encryptFile(
    inputPath: string,
    outputPath: string,
    key: string
  ): Promise<string>;
  decryptFile(inputPath: string, key: string): Promise<string>;
  getPublicRSAkey(privateRSAkey: string): string;
  getPublicECDSAKey(privateECDAkey: string): string;
  pbkdf2(
    password: string,
    salt: string,
    iterations: number,
    keyLength: number,
    hash: string
  ): string;
  getRandomBytes(size: number): string;
  encryptRSAOAEP(data: string, publicKey: string): string;
  decryptRSAOAEP(data: string, privateKey: string): string;
};

let Encryption: EncryptionModule;

if (Platform.OS === 'web') {
  // Use web-encryption for web
  Encryption = require('./web/index');
} else {
  // Use native TurboModules for mobile
  Encryption = require('./native/index');
}

export function generateAESKey(input: number): string {
  return Encryption.generateAESKey(input);
}

export function encryptAES(data: string, key: string): string {
  return Encryption.encryptAES(data, key);
}

export function decryptAES(data: string, key: string): string {
  return Encryption.decryptAES(data, key);
}

export function encryptRSA(data: string, key: string): string {
  return Encryption.encryptRSA(data, key);
}

export function decryptRSA(data: string, key: string): string {
  return Encryption.decryptRSA(data, key);
}

export function generateRSAKeyPair(): KeyPair {
  return Encryption.generateRSAKeyPair();
}

export function signDataRSA(data: string, key: string): string {
  return Encryption.signDataRSA(data, key);
}

export function verifySignatureRSA(
  data: string,
  signatureBase64: string,
  key: string
): boolean {
  return Encryption.verifySignatureRSA(data, signatureBase64, key);
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

export function hashSHA256(input: string): string {
  return Encryption.hashSHA256(input);
}

export function hashSHA512(input: string): string {
  return Encryption.hashSHA512(input);
}

export function generateRandomString(input: number): string {
  return Encryption.generateRandomString(input);
}

export function base64Encode(input: string): string {
  return Encryption.base64Encode(input);
}

export function base64Decode(input: string): string {
  return Encryption.base64Decode(input);
}

export function generateECDSAKeyPair(): KeyPair {
  return Encryption.generateECDSAKeyPair();
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

export function getPublicRSAkey(privateRSAkey: string): string {
  return Encryption.getPublicRSAkey(privateRSAkey);
}

export function getPublicECDSAKey(privateECDAkey: string): string {
  return Encryption.getPublicECDSAKey(privateECDAkey);
}

export function pbkdf2(
  password: string,
  salt: string,
  iterations: number,
  keyLength: number,
  hash: string
): string {
  return Encryption.pbkdf2(password, salt, iterations, keyLength, hash);
}

export function getRandomBytes(size: number): string {
  return Encryption.getRandomBytes(size);
}

export function encryptRSAOAEP(data: string, publicKey: string): string {
  return Encryption.encryptRSAOAEP(data, publicKey);
}

export function decryptRSAOAEP(data: string, privateKey: string): string {
  return Encryption.decryptRSAOAEP(data, privateKey);
}
