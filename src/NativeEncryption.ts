import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';
export interface keypair {
  publicKey: string;
  privateKey: string;
}
export interface Spec extends TurboModule {
  generateAESKey(keySize: number): string;
  encryptAES(data: string, key: string): string;
  decryptAES(data: string, key: string): string;
  encryptFile(
    inputPath: string,
    outputPath: string,
    key: string
  ): Promise<string>;
  decryptFile(inputPath: string, key: string): Promise<string>;
  encryptAsyncAES(data: string, key: string): Promise<string>;
  decryptAsyncAES(data: string, key: string): Promise<string>;

  generateRSAKeyPair(): keypair;
  getPublicRSAkey(privateRSAkey: string): string;
  encryptRSA(data: string, publicKey: string): string;
  decryptRSA(data: string, privateKey: string): string;
  encryptAsyncRSA(data: string, publicKey: string): Promise<string>;
  decryptAsyncRSA(data: string, privateKey: string): Promise<string>;

  hashSHA256(input: string): string;
  hashSHA512(input: string): string;

  generateHMACKey(keySize: number): string;
  hmacSHA256(data: string, key: string): string;
  hmacSHA512(data: string, key: string): string;

  generateRandomString(input: number): string;
  base64Encode(input: string): string;
  base64Decode(input: string): string;

  generateECDSAKeyPair(): keypair;
  getPublicECDSAKey(privateECDAkey: string): string;
  signDataECDSA(data: string, key: string): string;
  verifySignatureECDSA(
    data: string,
    signatureBase64: string,
    key: string
  ): boolean;
}

export default TurboModuleRegistry.getEnforcing<Spec>('Encryption');
