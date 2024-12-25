import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';

export interface Spec extends TurboModule {
  encryptAES(data: string, key: string): string;
  decryptAES(data: string, key: string): string;
  encryptRSA(data: string, publicKey: string): string;
  decryptRSA(data: string, privateKey: string): string;
  hashSHA256(input: string): string;
  hashSHA512(input: string): string;
  hmacSHA256(data: string, key: string): string;
  generateRandomString(input: number): string;
  base64Encode(input: string): string;
  base64Decode(input: string): string;
}

export default TurboModuleRegistry.getEnforcing<Spec>('Encryption');
