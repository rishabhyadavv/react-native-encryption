import type { ConfigPlugin } from 'expo/config-plugins';

const withEncryption: ConfigPlugin = (config) => {
  return config;
};

export default withEncryption;
