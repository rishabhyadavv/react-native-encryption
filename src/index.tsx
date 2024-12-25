import Encryption from './NativeEncryption';

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
export function hmacSHA256(data: string, key: string): string {
  return Encryption.hmacSHA256(data, key);
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
