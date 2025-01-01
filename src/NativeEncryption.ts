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
  encryptAsyncAES(data: string, key: string): Promise<string>;
  decryptAsyncAES(data: string, key: string): Promise<string>;
  encryptRSA(data: string, publicKey: string): string;
  decryptRSA(data: string, privateKey: string): string;
  encryptAsyncRSA(data: string, key: string): Promise<string>;
  decryptAsyncRSA(data: string, key: string): Promise<string>;
  hashSHA256(input: string): string;
  hashSHA512(input: string): string;
  hmacSHA256(data: string, key: string): string;
  generateRandomString(input: number): string;
  base64Encode(input: string): string;
  base64Decode(input: string): string;
  generateRSAKeyPair(): keypair;
  generateECDSAKeyPair(): keypair;
  signDataECDSA(data: string, key: string): string;
  verifySignatureECDSA(
    data: string,
    signatureBase64: string,
    key: string
  ): boolean;
}

export default TurboModuleRegistry.getEnforcing<Spec>('Encryption');
