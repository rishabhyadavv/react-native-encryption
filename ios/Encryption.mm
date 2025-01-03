#import "Encryption.h"
#import <CommonCrypto/CommonCrypto.h>
#import "react_native_encryption-Swift.h"

@implementation Encryption {
    CryptoUtility *cryptoUtil;
}
RCT_EXPORT_MODULE()

- (instancetype)init
{
    self = [super init];
    if (self) {
        cryptoUtil = [CryptoUtility new];
    }
    return self;
}

- (NSString *)generateAESKey:(double)keySize {
    return  [cryptoUtil generateAESKey:keySize];
}

#pragma mark - AES Encryption and Decryption
- (NSString *)generateAESKeyCryptoKit:(NSString *)data key:(NSString *)key {
    NSError *error = nil;
    NSString *encryptedString = [cryptoUtil encryptAES:data key:key errorObj:&error];
    
    if (error) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:error.localizedDescription
                                     userInfo:nil];
    } else {
        return encryptedString;
    }
}

-(NSDictionary *)generateECDSAKeyPair {
    NSError *error = nil;
    NSDictionary *keyPairs = [cryptoUtil generateECDSAKeyPair];
    
    if (error) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:error.localizedDescription
                                     userInfo:nil];
    } else {
        return keyPairs;
    }
    
}

- (NSString *)signDataECDSA:(NSString *)data key:(NSString *)key {
    NSError *error = nil;
    NSString *encryptedString = [cryptoUtil signDataECDSA:data privateKeyBase64:key errorObj:&error];
    
    if (error) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:error.localizedDescription
                                     userInfo:nil];
    } else {
        return encryptedString;
    }
}

- (NSNumber *)verifySignatureECDSA:(NSString *)data signatureBase64:(NSString *)signature key:(NSString *)key {
    NSError *error = nil;
    BOOL isValid = [cryptoUtil verifySignatureECDSA:data signatureBase64:signature publicKeyBase64:key errorObj:&error];
    
    if (error) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:error.localizedDescription
                                     userInfo:nil];
    } else {
        return @(isValid);
    }
}

- (NSString *)encryptAES:(NSString *)data key:(NSString *)key {
    NSError *error = nil;
    NSString *encryptedString = [cryptoUtil encryptAES:data key:key errorObj:&error];
    
    if (error) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:error.localizedDescription
                                     userInfo:nil];
    } else {
        return encryptedString;
    }
}

- (void)encryptAsyncAES:(NSString *)data key:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                 reject:(RCTPromiseRejectBlock)reject {
    
    __typeof(self) __weak weakSelf = self;
    // Run on a background thread to ensure it doesn't block the UI
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        __typeof(weakSelf) __strong strongSelf = weakSelf;
        if (!strongSelf) {
            reject(@"ENCRYPTION_ERROR", @"Encryption failed: self was deallocated", nil);
            return;
        }
        
        @try {
            NSError *error = nil;
            NSString *encryptedString = [strongSelf->cryptoUtil encryptAES:data key:key errorObj:&error];
            
                                 if (error) {
                reject(@"ENCRYPTION_ERROR", error.localizedDescription, nil);
                
            } else {
                resolve(encryptedString);
            }
        }
        @catch (NSException *exception) {
            reject(@"ENCRYPTION_EXCEPTION", exception.reason, nil);
        }
    });
}

- (void)encryptFile:(NSString *)inputPath outputPath:(NSString *)outputPath key:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                 reject:(RCTPromiseRejectBlock)reject {
    
    __typeof(self) __weak weakSelf = self;
    // Run on a background thread to ensure it doesn't block the UI
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        __typeof(weakSelf) __strong strongSelf = weakSelf;
        if (!strongSelf) {
            reject(@"ENCRYPTION_ERROR", @"Encryption failed: self was deallocated", nil);
            return;
        }
        
        @try {
            NSError *error = nil;
            NSString *encryptedString = [strongSelf->cryptoUtil encryptFile:inputPath outputPath:outputPath key:key errorObj:&error];
            
                                 if (error) {
                reject(@"ENCRYPTION_ERROR", error.localizedDescription, nil);
                
            } else {
                resolve(encryptedString);
            }
        }
        @catch (NSException *exception) {
            reject(@"ENCRYPTION_EXCEPTION", exception.reason, nil);
        }
    });
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
    
    NSError *error = nil;
    NSString *encryptedString = [cryptoUtil decryptAES:data key:key errorObj:&error];
    
    if (error) {
        @throw [NSException exceptionWithName:@"DecryptionError"
                                       reason:error.localizedDescription
                                     userInfo:nil];
    } else {
        return encryptedString;
    }
}

// AES Decryption
- (void)decryptAsyncAES:(NSString *)data key:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                 reject:(RCTPromiseRejectBlock)reject {
    
    __typeof(self) __weak weakSelf = self;
    // Run on a background thread to ensure it doesn't block the UI
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        __typeof(weakSelf) __strong strongSelf = weakSelf;
        if (!strongSelf) {
            reject(@"ENCRYPTION_ERROR", @"Encryption failed: self was deallocated", nil);
            return;
        }
        
        @try {
            NSError *error = nil;
            NSString *encryptedString = [strongSelf->cryptoUtil decryptAES:data key:key errorObj:&error];
            
                                 if (error) {
                reject(@"ENCRYPTION_ERROR", error.localizedDescription, nil);
                
            } else {
                resolve(encryptedString);
            }
        }
        @catch (NSException *exception) {
            reject(@"ENCRYPTION_EXCEPTION", exception.reason, nil);
        }
    });
}

- (void)decryptFile:(NSString *)inputPath key:(NSString *)key resolve:(RCTPromiseResolveBlock)resolve
                 reject:(RCTPromiseRejectBlock)reject {
    
    __typeof(self) __weak weakSelf = self;
    // Run on a background thread to ensure it doesn't block the UI
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        __typeof(weakSelf) __strong strongSelf = weakSelf;
        if (!strongSelf) {
            reject(@"ENCRYPTION_ERROR", @"Encryption failed: self was deallocated", nil);
            return;
        }
        
        @try {
            NSError *error = nil;
            NSString *encryptedString = [strongSelf->cryptoUtil decryptFile:inputPath key:key errorObj:&error];
            
                                 if (error) {
                reject(@"ENCRYPTION_ERROR", error.localizedDescription, nil);
                
            } else {
                resolve(encryptedString);
            }
        }
        @catch (NSException *exception) {
            reject(@"ENCRYPTION_EXCEPTION", exception.reason, nil);
        }
    });
}


#pragma mark - RSA Encryption and Decryption
-(NSDictionary *)generateRSAKeyPair {
    NSError *error = nil;
    NSDictionary *keyPairs = [cryptoUtil generateRSAKeyPair:&error];
    
    if (error) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:error.localizedDescription
                                     userInfo:nil];
    } else {
        return keyPairs;
    }
    
}

- (NSString *)encryptRSA:(NSString *)data publicKey:(NSString *)publicKey {
    NSError *error = nil;
    NSString *encryptedString = [cryptoUtil encryptRSA:data publicKeyBase64:publicKey errorObj:&error];
    
    if (error) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:error.localizedDescription
                                     userInfo:nil];
    } else {
        return encryptedString;
    }
}

- (void)encryptAsyncRSA:(NSString *)data publicKey:(NSString *)publicKey resolve:(RCTPromiseResolveBlock)resolve
                 reject:(RCTPromiseRejectBlock)reject {
    
    __typeof(self) __weak weakSelf = self;
    // Run on a background thread to ensure it doesn't block the UI
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        __typeof(weakSelf) __strong strongSelf = weakSelf;
        if (!strongSelf) {
            reject(@"ENCRYPTION_ERROR", @"Encryption failed: self was deallocated", nil);
            return;
        }
        
        @try {
            NSError *error = nil;
            NSString *encryptedString = [strongSelf->cryptoUtil encryptRSA:data publicKeyBase64:publicKey errorObj:&error];
            
                                 if (error) {
                reject(@"ENCRYPTION_ERROR", error.localizedDescription, nil);
                
            } else {
                resolve(encryptedString);
            }
        }
        @catch (NSException *exception) {
            reject(@"ENCRYPTION_EXCEPTION", exception.reason, nil);
        }
    });
}

- (NSString *)decryptRSA:(NSString *)data privateKey:(NSString *)privateKey {
    if (!data || !privateKey) {
        @throw [NSException exceptionWithName:@"DecryptionError"
                                       reason:@"Invalid encrypted data or private key"
                                     userInfo:nil];
    }
    
    NSError *error = nil;
    NSString *encryptedString = [cryptoUtil decryptRSA:data privateKeyBase64:privateKey errorObj:&error];
    
    if (error) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:error.localizedDescription
                                     userInfo:nil];
    } else {
        return encryptedString;
    }
}

- (void)decryptAsyncRSA:(NSString *)data privateKey:(NSString *)privateKey resolve:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject {
    
    __typeof(self) __weak weakSelf = self;
    // Run on a background thread to ensure it doesn't block the UI
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        __typeof(weakSelf) __strong strongSelf = weakSelf;
        if (!strongSelf) {
            reject(@"ENCRYPTION_ERROR", @"Encryption failed: self was deallocated", nil);
            return;
        }
        
        @try {
            NSError *error = nil;
            NSString *encryptedString = [strongSelf->cryptoUtil decryptRSA:data privateKeyBase64:privateKey errorObj:&error];
            
            if (error) {
                reject(@"ENCRYPTION_ERROR", error.localizedDescription, nil);
                
            } else {
                resolve(encryptedString);
            }
        }
        @catch (NSException *exception) {
            reject(@"ENCRYPTION_EXCEPTION", exception.reason, nil);
        }
    });
}


#pragma mark - Hashing

// SHA-256 Hashing
- (NSString *)hashSHA256:(NSString *)input {
    if (!input || input.length == 0) {
        @throw [NSException exceptionWithName:@"HashingError"
                                       reason:@"Input string cannot be nil or empty for SHA-256 hashing"
                                     userInfo:nil];
    }
    return [cryptoUtil hashSHA256:input];
}


// SHA-512 Hashing
- (NSString *)hashSHA512:(NSString *)input {
    if (!input || input.length == 0) {
        @throw [NSException exceptionWithName:@"HashingError"
                                       reason:@"Input string cannot be nil or empty for SHA-512 hashing"
                                     userInfo:nil];
    }
    
    return [cryptoUtil hashSHA512:input];
}


#pragma mark - HMAC

// HMAC-SHA256
- (NSString *)hmacSHA256:(NSString *)data key:(NSString *)key {
    NSError *error = nil;
    NSString *encryptedString = [cryptoUtil hmacSHA256:data key:key errorObj:&error];
    
    if (error) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:error.localizedDescription
                                     userInfo:nil];
    } else {
        return encryptedString;
    }
}


#pragma mark - Utilities

// Generate Random String
- (NSString *)generateRandomString:(double)length {
    NSError *error = nil;
    NSString *encryptedString = [cryptoUtil generateRandomString:length errorObj:&error];
    
    if (error) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:error.localizedDescription
                                     userInfo:nil];
    } else {
        return encryptedString;
    }
}




#pragma mark - Base64
- (NSString *)base64Encode:(NSString *)input {
    if (!input || input.length == 0) {
        @throw [NSException exceptionWithName:@"Base64Error"
                                       reason:@"Input string cannot be nil or empty for Base64 encoding"
                                     userInfo:nil];
    }
    
    // Encode NSData to Base64
    return [cryptoUtil base64Encode:input];
}



- (NSString *)base64Decode:(NSString *)input {
    if (!input || input.length == 0) {
        @throw [NSException exceptionWithName:@"Base64Error"
                                       reason:@"Base64 string cannot be nil or empty for decoding"
                                     userInfo:nil];
    }
    
    NSError *error = nil;
    NSString *encryptedString = [cryptoUtil base64Decode:input errorObj:&error];
    
    if (error) {
        @throw [NSException exceptionWithName:@"EncryptionError"
                                       reason:error.localizedDescription
                                     userInfo:nil];
    } else {
        return encryptedString;
    }
    
}


- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
(const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<facebook::react::NativeEncryptionSpecJSI>(params);
}

@end
