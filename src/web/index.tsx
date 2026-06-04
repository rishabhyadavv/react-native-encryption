// Web-specific implementation using web-encryption library
import * as WebEncryption from 'web-secure-encryption';

declare var crypto: any;
declare var atob: (input: string) => string;
declare var btoa: (input: string) => string;
declare var TextEncoder: { new (): { encode(input: string): Uint8Array } };

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
export const generateECDSAKeyPair = WebEncryption.generateECDSAKeyPair;
export const signDataECDSA = WebEncryption.signDataECDSA;
export const verifySignatureECDSA = WebEncryption.verifySignatureECDSA;
export const base64Encode = WebEncryption.base64Encode;
export const base64Decode = WebEncryption.base64Decode;
export const getPublicECDSAKey = WebEncryption.getPublicECDSAKey;

// --- Helpers ---

function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    hex += bytes[i]!.toString(16).padStart(2, '0');
  }
  return hex;
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binaryString: string = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer as ArrayBuffer;
}

function stringToUtf8Bytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

// --- Hash: output hex to match native (iOS/Android return lowercase hex) ---

export async function hashSHA256(input: string): Promise<string> {
  const data = stringToUtf8Bytes(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return arrayBufferToHex(hashBuffer);
}

export async function hashSHA512(input: string): Promise<string> {
  const data = stringToUtf8Bytes(input);
  const hashBuffer = await crypto.subtle.digest('SHA-512', data);
  return arrayBufferToHex(hashBuffer);
}

// --- HMAC: use raw key bytes (decode Base64) and output hex to match native ---

export async function generateHMACKey(keySize: number): Promise<string> {
  const key = await crypto.subtle.generateKey(
    { name: 'HMAC', hash: 'SHA-256', length: keySize },
    true,
    ['sign']
  );
  const rawKey = await crypto.subtle.exportKey('raw', key);
  const bytes = new Uint8Array(rawKey);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

export async function hmacSHA256(data: string, key: string): Promise<string> {
  const keyBytes = base64ToArrayBuffer(key);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const dataBytes = stringToUtf8Bytes(data);
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, dataBytes);
  return arrayBufferToHex(signature);
}

export async function hmacSHA512(data: string, key: string): Promise<string> {
  const keyBytes = base64ToArrayBuffer(key);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-512' },
    false,
    ['sign']
  );
  const dataBytes = stringToUtf8Bytes(data);
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, dataBytes);
  return arrayBufferToHex(signature);
}

// --- generateRandomString: produce alphanumeric string to match native ---

export async function generateRandomString(length: number): Promise<string> {
  const charset =
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += charset[randomValues[i]! % charset.length];
  }
  return result;
}

// --- getPublicRSAkey: extract public key from private key ---

export async function getPublicRSAkey(
  privateKeyBase64: string
): Promise<string> {
  const keyData = base64ToArrayBuffer(privateKeyBase64);
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    keyData,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  const publicJwk = {
    kty: jwk.kty,
    n: jwk.n,
    e: jwk.e,
    alg: jwk.alg,
    ext: true,
    key_ops: ['encrypt'],
  };
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    publicJwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
  const spkiBuffer = await crypto.subtle.exportKey('spki', publicKey);
  const spkiBytes = new Uint8Array(spkiBuffer);
  let binary = '';
  for (let i = 0; i < spkiBytes.byteLength; i++) {
    binary += String.fromCharCode(spkiBytes[i]!);
  }
  return btoa(binary);
}
