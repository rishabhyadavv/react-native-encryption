#import "Encryption.h"
#import <CommonCrypto/CommonCrypto.h>


@implementation Encryption
RCT_EXPORT_MODULE()

// Method to encrypt data
- (NSString *)encrypt:(NSString *)data key:(NSString *)key {
    NSError *error = nil;
    NSString *encryptedString = [self encryptData:data key:key error:&error];

    if (error) {
      return  @"error";
//        return @{
//            @"error": @{
//                @"code": @(error.code),
//                @"message": error.localizedDescription
//            }
//        };
    }
  
      return encryptedString;

//    return @{
//        @"result": encryptedString
//    };
}

- (NSString *)encryptData:(NSString *)data key:(NSString *)key error:(NSError **)error {
    NSData *dataToEncrypt = [data dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];

    size_t bufferSize = kCCBlockSizeAES128 + dataToEncrypt.length + kCCBlockSizeAES128;
    void *encryptedBuffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;

    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding,
                                          keyData.bytes,
                                          keyData.length,
                                          NULL,
                                          dataToEncrypt.bytes,
                                          dataToEncrypt.length,
                                          encryptedBuffer,
                                          bufferSize,
                                          &numBytesEncrypted);

    if (cryptStatus == kCCSuccess) {
        NSData *encryptedData = [NSData dataWithBytesNoCopy:encryptedBuffer length:numBytesEncrypted];
        return [encryptedData base64EncodedStringWithOptions:0];
    } else {
        free(encryptedBuffer);
        if (error) {
            *error = [NSError errorWithDomain:@"EncryptionError"
                                         code:cryptStatus
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to encrypt data"}];
        }
        return nil;
    }
}

- (NSString *)decrypt:(NSString *)encryptedData key:(NSString *)key {
    NSError *error = nil;
    NSString *decryptedString = [self decryptData:encryptedData key:key error:&error];

    if (error) {
      return @"Error";
//        return @{
//            @"error": @{
//                @"code": @(error.code),
//                @"message": error.localizedDescription
//            }
//        };
    }
  
  return  decryptedString;

//    return @{
//        @"result": decryptedString
//    };
}

- (NSString *)decryptData:(NSString *)encryptedData key:(NSString *)key error:(NSError **)error {
    NSData *encryptedDataBytes = [[NSData alloc] initWithBase64EncodedString:encryptedData options:0];
    if (!encryptedDataBytes) {
        if (error) {
            *error = [NSError errorWithDomain:@"DecryptionError"
                                         code:-1
                                     userInfo:@{NSLocalizedDescriptionKey: @"Invalid encrypted data"}];
        }
        return nil;
    }

    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    size_t bufferSize = encryptedDataBytes.length + kCCBlockSizeAES128;
    void *decryptedBuffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;

    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding,
                                          keyData.bytes,
                                          keyData.length,
                                          NULL,
                                          encryptedDataBytes.bytes,
                                          encryptedDataBytes.length,
                                          decryptedBuffer,
                                          bufferSize,
                                          &numBytesDecrypted);

    if (cryptStatus == kCCSuccess) {
        NSData *decryptedData = [NSData dataWithBytesNoCopy:decryptedBuffer length:numBytesDecrypted];
        NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
        return decryptedString;
    } else {
        free(decryptedBuffer);
        if (error) {
            *error = [NSError errorWithDomain:@"DecryptionError"
                                         code:cryptStatus
                                     userInfo:@{NSLocalizedDescriptionKey: @"Failed to decrypt data"}];
        }
        return nil;
    }
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<facebook::react::NativeEncryptionSpecJSI>(params);
}

@end
