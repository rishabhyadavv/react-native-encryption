import Encryption from './NativeEncryption';

export function encrypt(data: string, key: string): string {
  return Encryption.encrypt(data, key);
}
export function decrypt(data: string, key: string): string {
  return Encryption.decrypt(data, key);
}
