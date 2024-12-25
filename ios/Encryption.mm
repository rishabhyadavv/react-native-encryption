#import "Encryption.h"
#import <CommonCrypto/CommonCrypto.h>


@implementation Encryption
RCT_EXPORT_MODULE()

// // Method to encrypt data
// - (NSString *)encrypt:(NSString *)data key:(NSString *)key {
//     NSError *error = nil;
//     NSString *encryptedString = [self encryptData:data key:key error:&error];

//     if (error) {
//       return  @"error";
// //        return @{
// //            @"error": @{
// //                @"code": @(error.code),
// //                @"message": error.localizedDescription
// //            }
// //        };
//     }
  
//       return encryptedString;

// //    return @{
// //        @"result": encryptedString
// //    };
// }

// - (NSString *)encryptData:(NSString *)data key:(NSString *)key error:(NSError **)error {
//     NSData *dataToEncrypt = [data dataUsingEncoding:NSUTF8StringEncoding];
//     NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];

//     size_t bufferSize = kCCBlockSizeAES128 + dataToEncrypt.length + kCCBlockSizeAES128;
//     void *encryptedBuffer = malloc(bufferSize);
//     size_t numBytesEncrypted = 0;

//     CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
//                                           kCCAlgorithmAES,
//                                           kCCOptionPKCS7Padding,
//                                           keyData.bytes,
//                                           keyData.length,
//                                           NULL,
//                                           dataToEncrypt.bytes,
//                                           dataToEncrypt.length,
//                                           encryptedBuffer,
//                                           bufferSize,
//                                           &numBytesEncrypted);

//     if (cryptStatus == kCCSuccess) {
//         NSData *encryptedData = [NSData dataWithBytesNoCopy:encryptedBuffer length:numBytesEncrypted];
//         return [encryptedData base64EncodedStringWithOptions:0];
//     } else {
//         free(encryptedBuffer);
//         if (error) {
//             *error = [NSError errorWithDomain:@"EncryptionError"
//                                          code:cryptStatus
//                                      userInfo:@{NSLocalizedDescriptionKey: @"Failed to encrypt data"}];
//         }
//         return nil;
//     }
// }

// - (NSString *)decrypt:(NSString *)encryptedData key:(NSString *)key {
//     NSError *error = nil;
//     NSString *decryptedString = [self decryptData:encryptedData key:key error:&error];

//     if (error) {
//       return @"Error";
// //        return @{
// //            @"error": @{
// //                @"code": @(error.code),
// //                @"message": error.localizedDescription
// //            }
// //        };
//     }
  
//   return  decryptedString;

// //    return @{
// //        @"result": decryptedString
// //    };
// }

// - (NSString *)decryptData:(NSString *)encryptedData key:(NSString *)key error:(NSError **)error {
//     NSData *encryptedDataBytes = [[NSData alloc] initWithBase64EncodedString:encryptedData options:0];
//     if (!encryptedDataBytes) {
//         if (error) {
//             *error = [NSError errorWithDomain:@"DecryptionError"
//                                          code:-1
//                                      userInfo:@{NSLocalizedDescriptionKey: @"Invalid encrypted data"}];
//         }
//         return nil;
//     }

//     NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
//     size_t bufferSize = encryptedDataBytes.length + kCCBlockSizeAES128;
//     void *decryptedBuffer = malloc(bufferSize);
//     size_t numBytesDecrypted = 0;

//     CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
//                                           kCCAlgorithmAES,
//                                           kCCOptionPKCS7Padding,
//                                           keyData.bytes,
//                                           keyData.length,
//                                           NULL,
//                                           encryptedDataBytes.bytes,
//                                           encryptedDataBytes.length,
//                                           decryptedBuffer,
//                                           bufferSize,
//                                           &numBytesDecrypted);

//     if (cryptStatus == kCCSuccess) {
//         NSData *decryptedData = [NSData dataWithBytesNoCopy:decryptedBuffer length:numBytesDecrypted];
//         NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
//         return decryptedString;
//     } else {
//         free(decryptedBuffer);
//         if (error) {
//             *error = [NSError errorWithDomain:@"DecryptionError"
//                                          code:cryptStatus
//                                      userInfo:@{NSLocalizedDescriptionKey: @"Failed to decrypt data"}];
//         }
//         return nil;
//     }
// }


#pragma mark - AES Encryption and Decryption
- (NSString *)encryptAES:(NSString *)data key:(NSString *)key {
    if (!data || !key) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:@"Invalid data or key"
                                     userInfo:nil];
    }

    // Convert data and key to NSData
    NSData *dataToEncrypt = [data dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    
    if (keyData.length != kCCKeySizeAES128 && keyData.length != kCCKeySizeAES192 && keyData.length != kCCKeySizeAES256) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:@"Invalid AES key size. Must be 128, 192, or 256 bits."
                                     userInfo:nil];
    }

    // Allocate buffer for encryption
    size_t bufferSize = kCCBlockSizeAES128 + dataToEncrypt.length + kCCBlockSizeAES128;
    void *encryptedBuffer = malloc(bufferSize);
    if (!encryptedBuffer) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:@"Failed to allocate memory for encryption buffer"
                                     userInfo:nil];
    }
    
    size_t numBytesEncrypted = 0;

    // Perform AES encryption
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding,
                                          keyData.bytes,
                                          keyData.length,
                                          NULL, // No IV (Initialization Vector)
                                          dataToEncrypt.bytes,
                                          dataToEncrypt.length,
                                          encryptedBuffer,
                                          bufferSize,
                                          &numBytesEncrypted);

    if (cryptStatus == kCCSuccess) {
        NSData *encryptedData = [NSData dataWithBytesNoCopy:encryptedBuffer length:numBytesEncrypted freeWhenDone:YES];
        return [encryptedData base64EncodedStringWithOptions:0];
    } else {
        free(encryptedBuffer);
        NSString *errorMessage = [self cryptorStatusToString:cryptStatus];
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:errorMessage
                                     userInfo:nil];
    }
}

- (NSString *)cryptorStatusToString:(CCCryptorStatus)status {
    switch (status) {
        case kCCSuccess:
            return @"Success";
        case kCCParamError:
            return @"Parameter Error";
        case kCCBufferTooSmall:
            return @"Buffer Too Small";
        case kCCMemoryFailure:
            return @"Memory Failure";
        case kCCAlignmentError:
            return @"Alignment Error";
        case kCCDecodeError:
            return @"Decode Error";
        case kCCUnimplemented:
            return @"Unimplemented";
        default:
            return [NSString stringWithFormat:@"Unknown Error (Status Code: %d)", status];
    }
}



  // AES Decryption
- (NSString *)decryptAES:(NSString *)data key:(NSString *)key {
    if (!data || !key) {
        @throw [NSException exceptionWithName:@"DecryptionError"
                                       reason:@"Invalid data or key"
                                     userInfo:nil];
    }

    // Decode Base64-encoded encrypted data
    NSData *encryptedData = [[NSData alloc] initWithBase64EncodedString:data options:0];
    if (!encryptedData) {
        @throw [NSException exceptionWithName:@"DecryptionError"
                                       reason:@"Failed to decode encrypted data from Base64"
                                     userInfo:nil];
    }

    // Convert key to NSData
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    if (!keyData || (keyData.length != kCCKeySizeAES128 && keyData.length != kCCKeySizeAES192 && keyData.length != kCCKeySizeAES256)) {
        @throw [NSException exceptionWithName:@"DecryptionError"
                                       reason:@"Invalid AES key size. Must be 128, 192, or 256 bits."
                                     userInfo:nil];
    }

    // Allocate buffer for decryption
    size_t bufferSize = encryptedData.length + kCCBlockSizeAES128;
    void *decryptedBuffer = malloc(bufferSize);
    if (!decryptedBuffer) {
        @throw [NSException exceptionWithName:@"DecryptionError"
                                       reason:@"Failed to allocate memory for decryption buffer"
                                     userInfo:nil];
    }

    size_t numBytesDecrypted = 0;

    // Perform AES Decryption
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES,
                                          kCCOptionPKCS7Padding,
                                          keyData.bytes,
                                          keyData.length,
                                          NULL, // No IV (Initialization Vector)
                                          encryptedData.bytes,
                                          encryptedData.length,
                                          decryptedBuffer,
                                          bufferSize,
                                          &numBytesDecrypted);

    if (cryptStatus == kCCSuccess) {
        NSData *decryptedData = [NSData dataWithBytesNoCopy:decryptedBuffer length:numBytesDecrypted freeWhenDone:YES];
        NSString *decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];

        if (!decryptedString) {
            @throw [NSException exceptionWithName:@"DecryptionError"
                                           reason:@"Failed to convert decrypted data to a UTF-8 string"
                                         userInfo:nil];
        }

        return decryptedString;
    } else {
        free(decryptedBuffer);
        NSString *errorMessage = [self cryptorStatusToString:cryptStatus];
        @throw [NSException exceptionWithName:@"DecryptionError"
                                       reason:errorMessage
                                     userInfo:nil];
    }
}


  #pragma mark - RSA Encryption and Decryption

- (NSString *)encryptRSA:(NSString *)data publicKey:(NSString *)publicKey {
    if (!data || !publicKey) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:@"Invalid data or public key"
                                     userInfo:nil];
    }

    NSData *encrypteddata = [data dataUsingEncoding:NSUTF8StringEncoding];
    if (!data) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:@"Failed to convert data string to NSData"
                                     userInfo:nil];
    }

    SecKeyRef secPublicKey = [self createPublicKeyFromString:publicKey];
    if (!publicKey) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:@"Failed to create public key"
                                     userInfo:nil];
    }

    CFErrorRef error = NULL;
  NSData *encryptedData = (NSData *)CFBridgingRelease(SecKeyCreateEncryptedData(secPublicKey,
                                                                                kSecKeyAlgorithmRSAEncryptionPKCS1,
                                                                                (__bridge CFDataRef)encrypteddata,
                                                                                &error));
    CFRelease(secPublicKey);

    if (encryptedData) {
        return [encryptedData base64EncodedStringWithOptions:0];
    } else {
        NSString *errorMessage = (__bridge_transfer NSString *)CFErrorCopyDescription(error);
        CFRelease(error);
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:errorMessage ?: @"Failed to encrypt data with RSA"
                                     userInfo:nil];
    }
}


- (NSString *)decryptRSA:(NSString *)data privateKey:(NSString *)privateKey {
    if (!data || !privateKey) {
        @throw [NSException exceptionWithName:@"DecryptionError"
                                       reason:@"Invalid encrypted data or private key"
                                     userInfo:nil];
    }

    NSData *encryptedData = [[NSData alloc] initWithBase64EncodedString:data options:0];
    if (!encryptedData) {
        @throw [NSException exceptionWithName:@"DecryptionError"
                                       reason:@"Failed to decode encrypted data from Base64"
                                     userInfo:nil];
    }

    SecKeyRef secPrivateKey = [self createPrivateKeyFromString:privateKey];
    if (!privateKey) {
        @throw [NSException exceptionWithName:@"DecryptionError"
                                       reason:@"Failed to create private key"
                                     userInfo:nil];
    }

    CFErrorRef error = NULL;
  NSData *decryptedData = (NSData *)CFBridgingRelease(SecKeyCreateDecryptedData(secPrivateKey,
                                                                                kSecKeyAlgorithmRSAEncryptionPKCS1,
                                                                                (__bridge CFDataRef)encryptedData,
                                                                                &error));
    CFRelease(secPrivateKey);

    if (decryptedData) {
        return [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
    } else {
        NSString *errorMessage = (__bridge_transfer NSString *)CFErrorCopyDescription(error);
        CFRelease(error);
        @throw [NSException exceptionWithName:@"DecryptionError"
                                       reason:errorMessage ?: @"Failed to decrypt data with RSA"
                                     userInfo:nil];
    }
}


- (SecKeyRef)createPublicKeyFromString:(NSString *)keyString {
    if (!keyString || keyString.length == 0) {
        @throw [NSException exceptionWithName:@"KeyCreationError"
                                       reason:@"Public key string is empty or nil"
                                     userInfo:nil];
    }

    // Strip headers and decode Base64
    NSData *keyData = [self stripKeyHeader:[keyString dataUsingEncoding:NSUTF8StringEncoding]];
    if (!keyData) {
        @throw [NSException exceptionWithName:@"KeyCreationError"
                                       reason:@"Failed to process public key string"
                                     userInfo:nil];
    }

    // Define key creation options
    NSDictionary *options = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
        (__bridge id)kSecAttrKeySizeInBits: @(2048)
    };

    CFErrorRef error = NULL;
    SecKeyRef keyRef = SecKeyCreateWithData((__bridge CFDataRef)keyData,
                                            (__bridge CFDictionaryRef)options,
                                            &error);

    if (!keyRef || error != NULL) {
        NSString *errorDescription = (__bridge_transfer NSString *)CFErrorCopyDescription(error);
        CFRelease(error);
        @throw [NSException exceptionWithName:@"KeyCreationError"
                                       reason:errorDescription ?: @"Failed to create public key"
                                     userInfo:nil];
    }

    return keyRef;
}



- (SecKeyRef)createPrivateKeyFromString:(NSString *)keyString {
    if (!keyString || keyString.length == 0) {
        @throw [NSException exceptionWithName:@"KeyCreationError"
                                       reason:@"Private key string is empty or nil"
                                     userInfo:nil];
    }

    // Strip PEM headers and whitespace
    NSData *keyData = [self stripKeyHeader:[keyString dataUsingEncoding:NSUTF8StringEncoding]];
    if (!keyData) {
        @throw [NSException exceptionWithName:@"KeyCreationError"
                                       reason:@"Failed to process private key string"
                                     userInfo:nil];
    }

    // Log the key data for debugging
    NSLog(@"Private Key Data: %@", keyData);

    // Key attributes for PKCS#8 RSA private key
    NSDictionary *options = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
        (__bridge id)kSecAttrKeySizeInBits: @(2048)
    };

    CFErrorRef error = NULL;
    SecKeyRef keyRef = SecKeyCreateWithData((__bridge CFDataRef)keyData,
                                            (__bridge CFDictionaryRef)options,
                                            &error);

    if (!keyRef || error != NULL) {
        NSString *errorMessage = (__bridge_transfer NSString *)CFErrorCopyDescription(error);
        if (error) CFRelease(error);

        NSLog(@"Key Creation Error: %@", errorMessage);
        @throw [NSException exceptionWithName:@"KeyCreationError"
                                       reason:errorMessage ?: @"Failed to create private key"
                                     userInfo:nil];
    }

    return keyRef;
}




- (NSData *)stripKeyHeader:(NSData *)keyData {
    if (!keyData) {
        return nil;
    }

    NSString *keyString = [[NSString alloc] initWithData:keyData encoding:NSUTF8StringEncoding];
    if (!keyString) {
        return nil;
    }

    // Remove PEM headers and footers
    keyString = [keyString stringByReplacingOccurrencesOfString:@"-----BEGIN PRIVATE KEY-----" withString:@""];
    keyString = [keyString stringByReplacingOccurrencesOfString:@"-----END PRIVATE KEY-----" withString:@""];
    keyString = [keyString stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    keyString = [keyString stringByReplacingOccurrencesOfString:@" " withString:@""];

    // Decode the Base64 string
    NSData *strippedKeyData = [[NSData alloc] initWithBase64EncodedString:keyString options:0];
    if (!strippedKeyData) {
        @throw [NSException exceptionWithName:@"KeyCreationError"
                                       reason:@"Failed to decode Base64 RSA Private Key"
                                     userInfo:nil];
    }

    return strippedKeyData;
}




  #pragma mark - Hashing

  // SHA-256 Hashing
- (NSString *)hashSHA256:(NSString *)input {
    if (!input || input.length == 0) {
        @throw [NSException exceptionWithName:@"HashingError"
                                       reason:@"Input string cannot be nil or empty for SHA-256 hashing"
                                     userInfo:nil];
    }

    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding];
    if (!data) {
        @throw [NSException exceptionWithName:@"HashingError"
                                       reason:@"Failed to convert input string to NSData"
                                     userInfo:nil];
    }

    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    if (!CC_SHA256(data.bytes, (CC_LONG)data.length, digest)) {
        @throw [NSException exceptionWithName:@"HashingError"
                                       reason:@"Failed to compute SHA-256 hash"
                                     userInfo:nil];
    }

    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }

    return output;
}


  // SHA-512 Hashing
- (NSString *)hashSHA512:(NSString *)input {
    if (!input || input.length == 0) {
        @throw [NSException exceptionWithName:@"HashingError"
                                       reason:@"Input string cannot be nil or empty for SHA-512 hashing"
                                     userInfo:nil];
    }

    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding];
    if (!data) {
        @throw [NSException exceptionWithName:@"HashingError"
                                       reason:@"Failed to convert input string to NSData"
                                     userInfo:nil];
    }

    uint8_t digest[CC_SHA512_DIGEST_LENGTH];
    if (!CC_SHA512(data.bytes, (CC_LONG)data.length, digest)) {
        @throw [NSException exceptionWithName:@"HashingError"
                                       reason:@"Failed to compute SHA-512 hash"
                                     userInfo:nil];
    }

    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA512_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }

    return output;
}


  #pragma mark - HMAC

  // HMAC-SHA256
- (NSString *)hmacSHA256:(NSString *)data key:(NSString *)key {
    if (!data || data.length == 0) {
        @throw [NSException exceptionWithName:@"HMACError"
                                       reason:@"Message string cannot be nil or empty for HMAC-SHA256"
                                     userInfo:nil];
    }

    if (!key || key.length == 0) {
        @throw [NSException exceptionWithName:@"HMACError"
                                       reason:@"Key string cannot be nil or empty for HMAC-SHA256"
                                     userInfo:nil];
    }

    const char *cKey = [key cStringUsingEncoding:NSUTF8StringEncoding];
    const char *cData = [data cStringUsingEncoding:NSUTF8StringEncoding];
    if (!cKey || !cData) {
        @throw [NSException exceptionWithName:@"HMACError"
                                       reason:@"Failed to convert strings to C-style strings"
                                     userInfo:nil];
    }

    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, cKey, strlen(cKey), cData, strlen(cData), digest);

    NSMutableString *output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [output appendFormat:@"%02x", digest[i]];
    }

    return output;
}


  #pragma mark - Utilities

  // Generate Random String
- (NSString *)generateRandomString:(double)length {
    NSInteger validLength = (NSInteger)length; // Explicit conversion to NSInteger

    if (validLength <= 0) {
        @throw [NSException exceptionWithName:@"RandomStringError"
                                       reason:@"Length must be greater than zero"
                                     userInfo:nil];
    }

    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    NSUInteger charsetLength = sizeof(charset) - 1;

    NSMutableString *randomString = [NSMutableString stringWithCapacity:validLength];
    uint8_t *buffer = (uint8_t *)malloc(validLength * sizeof(uint8_t));

    if (!buffer) {
        @throw [NSException exceptionWithName:@"RandomStringError"
                                       reason:@"Failed to allocate memory for random string"
                                     userInfo:nil];
    }

    if (SecRandomCopyBytes(kSecRandomDefault, validLength, buffer) == errSecSuccess) {
        for (NSInteger i = 0; i < validLength; i++) {
            [randomString appendFormat:@"%C", charset[buffer[i] % charsetLength]];
        }
    } else {
        free(buffer);
        @throw [NSException exceptionWithName:@"RandomStringError"
                                       reason:@"Failed to generate secure random bytes"
                                     userInfo:nil];
    }

    free(buffer);
    return randomString;
}




  #pragma mark - Base64
- (NSString *)base64Encode:(NSString *)input {
    if (!input || input.length == 0) {
        @throw [NSException exceptionWithName:@"Base64Error"
                                       reason:@"Input string cannot be nil or empty for Base64 encoding"
                                     userInfo:nil];
    }

    // Convert the input string to NSData
    NSData *data = [input dataUsingEncoding:NSUTF8StringEncoding];
    if (!data) {
        @throw [NSException exceptionWithName:@"Base64Error"
                                       reason:@"Failed to convert input string to NSData"
                                     userInfo:nil];
    }

    // Encode NSData to Base64
    return [data base64EncodedStringWithOptions:0];
}



- (NSString *)base64Decode:(NSString *)input {
    if (!input || input.length == 0) {
        @throw [NSException exceptionWithName:@"Base64Error"
                                       reason:@"Base64 string cannot be nil or empty for decoding"
                                     userInfo:nil];
    }

    NSData *decodedData = [[NSData alloc] initWithBase64EncodedString:input options:0];
    if (!decodedData) {
        @throw [NSException exceptionWithName:@"Base64Error"
                                       reason:@"Failed to decode Base64 string"
                                     userInfo:nil];
    }

    NSString *decodedString = [[NSString alloc] initWithData:decodedData encoding:NSUTF8StringEncoding];
    if (!decodedString) {
        @throw [NSException exceptionWithName:@"Base64Error"
                                       reason:@"Failed to convert decoded data to UTF-8 string"
                                     userInfo:nil];
    }

    return decodedString;
}


- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<facebook::react::NativeEncryptionSpecJSI>(params);
}

@end
