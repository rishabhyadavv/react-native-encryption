import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';

export interface Spec extends TurboModule {
  encrypt(data: string, key: string): string;
  decrypt(data: string, key: string): string;
}

export default TurboModuleRegistry.getEnforcing<Spec>('Encryption');
