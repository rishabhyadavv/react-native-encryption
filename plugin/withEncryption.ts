// plugin/withEncryption.ts
import type { ConfigPlugin } from 'expo/config-plugins';

const withEncryption: ConfigPlugin = (config) => {
  // No extra changes needed (no permissions, no Info.plist edits, etc.)
  // Just return config untouched so Expo knows the plugin exists
  return config;
};

export default withEncryption;
