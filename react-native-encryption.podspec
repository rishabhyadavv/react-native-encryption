require "json"

package = JSON.parse(File.read(File.join(__dir__, "package.json")))
folly_compiler_flags = '-DFOLLY_NO_CONFIG -DFOLLY_MOBILE=1 -DFOLLY_USE_LIBCPP=1 -Wno-comma -Wno-shorten-64-to-32'

Pod::Spec.new do |s|
  s.name         = "react-native-encryption"
  s.version      = package["version"]
  s.summary      = package["description"]
  s.homepage     = package["homepage"]
  s.license      = package["license"]
  s.authors      = package["author"]

  s.platforms    = { :ios => min_ios_version_supported }
  s.source       = { :git => "https://github.com/rishabhyadavv/react-native-encryption.git", :tag => "#{s.version}" }

  s.source_files = "ios/**/*.{h,m,mm,cpp,swift}"
  s.private_header_files = "ios/**/*.h"
  
  # Swift configuration
  s.swift_version = "5.0"
  # Explicitly set module name to ensure Swift bridging header is generated correctly
  s.module_name = "react_native_encryption"
  
  swift_header_search_paths = "\"$(PODS_TARGET_SRCROOT)/ios\" \"$(DERIVED_SOURCES_DIR)\" \"$(PODS_CONFIGURATION_BUILD_DIR)/react-native-encryption\" \"$(CONFIGURATION_BUILD_DIR)/react-native-encryption\""
  swift_header_config = {
    "DEFINES_MODULE" => "YES",
    "CLANG_ENABLE_MODULES" => "YES",
    "SWIFT_INSTALL_OBJC_HEADER" => "YES",
    "SWIFT_OBJC_INTERFACE_HEADER_NAME" => "react_native_encryption-Swift.h",
    "SWIFT_COMPILATION_MODE" => "wholemodule",
    "HEADER_SEARCH_PATHS" => "$(inherited) #{swift_header_search_paths}"
  }
  merge_xcconfig = lambda do |base_config, extra_config|
    merged_config = (base_config || {}).merge(extra_config)
    header_search_paths = [base_config && base_config["HEADER_SEARCH_PATHS"], extra_config["HEADER_SEARCH_PATHS"]].compact.join(" ")
    merged_config["HEADER_SEARCH_PATHS"] = header_search_paths unless header_search_paths.empty?
    merged_config
  end
  
  # Use install_modules_dependencies helper to install the dependencies if React Native version >=0.71.0.
  # See https://github.com/facebook/react-native/blob/febf6b7f33fdb4904669f99d795eba4c0f95d7bf/scripts/cocoapods/new_architecture.rb#L79.
  if respond_to?(:install_modules_dependencies, true)
    install_modules_dependencies(s)
    s.pod_target_xcconfig = merge_xcconfig.call(s.attributes_hash["pod_target_xcconfig"], swift_header_config)
  else
    s.dependency "React-Core"

    # Don't install the dependencies when we run `pod install` in the old architecture.
    if ENV['RCT_NEW_ARCH_ENABLED'] == '1' then
      s.compiler_flags = folly_compiler_flags + " -DRCT_NEW_ARCH_ENABLED=1"
      s.pod_target_xcconfig    = merge_xcconfig.call(swift_header_config, {
          "HEADER_SEARCH_PATHS" => "$(inherited) \"$(PODS_ROOT)/boost\"",
          "OTHER_CPLUSPLUSFLAGS" => "-DFOLLY_NO_CONFIG -DFOLLY_MOBILE=1 -DFOLLY_USE_LIBCPP=1",
          "CLANG_CXX_LANGUAGE_STANDARD" => "c++17"
      })
      s.dependency "React-Codegen"
      s.dependency "RCT-Folly"
      s.dependency "RCTRequired"
      s.dependency "RCTTypeSafety"
      s.dependency "ReactCommon/turbomodule/core"
    else
      # Old architecture configuration
      s.pod_target_xcconfig = swift_header_config
    end
  end
end
