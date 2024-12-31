const {
  withAndroidManifest,
  withInfoPlist,
  createRunOncePlugin,
} = require('@expo/config-plugins');

const pkg = require('./package.json');

// Expo Plugin Main Function
const withNativeEncryption = (config) => {
  // ✅ iOS Configuration
  config = withInfoPlist(config, (config) => {
    config.modResults.NSAppTransportSecurity = {
      NSAllowsArbitraryLoads: true,
    };
    // config.modResults.NativeEncryptionEnabled = true;
    return config;
  });

  return config;
};

// Export Plugin
module.exports = createRunOncePlugin(
  withNativeEncryption,
  pkg.name,
  pkg.version
);
