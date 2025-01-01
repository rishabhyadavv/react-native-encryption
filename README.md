# 📚 **React Native Integration Guide for `rn-encryption` Library**

This guide explains how to directly access methods from the `rn-encryption` library in a **React Native project**, including usage examples for AES, RSA, Hashing, HMAC, Random String, and Base64 utilities.

---

## 📑 **Table of Contents**

1. [Library Installation](#1-library-installation)
2. [Requirements](#2-new_arch_needed)  
3. [Setup in React Native](#3-setup-in-react-native)  
4. [Direct Method Import](#4-direct-method-import)  
5. [API Overview](#5-api-overview)  
6. [Usage Examples](#6-usage-examples)  
7. [Troubleshooting](#7-troubleshooting)  
8. [Best Practices](#8-best-practices)  
9. [FAQ](#9-faq)
10. [Security Best Practices](#security-best-practices)

---

## 🚀 **1. Library Installation**

### 1.1 **Add Dependency**

Install the library using npm or yarn:

```bash
expo install @yourorg/native-encryption

# OR
npm install rn-encryption --save
# OR
yarn add rn-encryption
```

### 1.2 **Rebuild the Project**

For Android:
```bash
cd android && ./gradlew clean && cd ..
npx react-native run-android
```

For iOS:
```bash
cd ios && pod install && cd ..
npx react-native run-ios
```

---
## **2.Requirements**
  ### 2.1 **New Architecture required**
  New architecture required. React native >= 0.76.5 Works with Expo **Bare Workflow** & **Vanilla React Native**
  ### 2.2 **iOS: Cryptokit from swift is being used for encryption. Minimin support iOS version is 13.0**

---

## ⚙️ **3. Setup in React Native**

No additional configuration is required. The methods can be **directly imported** and used.

---

## 📦 **4. Direct Method Import**

You can directly import the methods you need:

```tsx
import {
  encryptAES,
  decryptAES,
  encryptRSA,
  decryptRSA,
  hashSHA256,
  hashSHA512,
  hmacSHA256,
  base64Encode,
  base64Decode,
  generateRandomString,
  generateAESKey,
  generateRSAKeyPair,
  generateECDSAKeyPair,
  signDataECDSA,
  verifySignatureECDSA,
  encryptAsyncAES,
  decryptAsyncAES,
  encryptAsyncRSA,
  decryptAsyncRSA
} from 'rn-encryption';;
```

Each method can be accessed directly without a default object wrapper.

---

## 📚 **5. API Overview**

### 🔒 **AES Encryption/Decryption**
- **`generateAESKey(keySize: number): string`**  
- **`encryptAES(data: string, key: string): string`**  
- **`decryptAES(data: string, key: string): string`**

### 🔑 **RSA Encryption/Decryption**
- **`generateRSAKeyPair(): keypair`**  
- **`encryptRSA(data: string, publicKey: string): string`**  
- **`decryptRSA(data: string, privateKey: string): string`**

### 🛡️ **SHA Hashing**
- **`hashSHA256(input: string): string`**  
- **`hashSHA512(input: string): string`**

### 📝 **HMAC-SHA256**
- **`hmacSHA256(data: string, key: string): string`**

### 🎲 **Random String Generation**
- **`generateRandomString(input: number): string`**

### 📝 **Base64 Encoding/Decoding**
- **`base64Encode(input: string): string`**  
- **`base64Decode(input: string): string`**

### 🔒 **ECDA Encryption/Decryption**
- **`generateECDSAKeyPair(): keypair`**  
- **`signDataECDSA(data: string, key: string): string`**  
- **`verifySignatureECDSA(data: string,signatureBase64: string, key: string): boolean`**

### 🔒 **Asynchronous Methods**
- **`encryptAsyncAES(data: string, key: string): Promise<string>`**
- **`decryptAsyncAES(data: string, key: string): Promise<string>`**
- **` encryptAsyncRSA(data: string, key: string): Promise<string>`**
- **`decryptAsyncRSA(data: string, key: string): Promise<string>`**
---

## 🛠️ **6. Usage Examples**

```tsx
import { useState } from 'react';
import { View, StyleSheet, Text, Button } from 'react-native';
import {
  encryptAES,
  decryptAES,
  encryptRSA,
  decryptRSA,
  hashSHA256,
  hashSHA512,
  hmacSHA256,
  base64Encode,
  base64Decode,
  generateRandomString,
  generateAESKey,
  generateRSAKeyPair,
  generateECDSAKeyPair,
  signDataECDSA,
  verifySignatureECDSA,
  encryptAsyncAES,
  decryptAsyncAES,
  encryptAsyncRSA,
  decryptAsyncRSA
} from 'rn-encryption';
interface EncryptionError {
  name: string;
  message: string;
}
export default function DashboardScreen() {
  const [result, setResult] = useState(''); // Encryption/Decryption result

   function handleRSAEncryption() {
    const plaintext = 'Hello, RSA Encryption!';
    const generatedKeys = generateRSAKeyPair();
    try {
      // Step 1: Encrypt the plaintext using the Public Key
      const encryptedData =  encryptRSA(
        plaintext,
        generatedKeys.publicKey
      );
      // Step 2: Decrypt the encrypted data using the Private Key
      const decryptedData =  decryptRSA(
        encryptedData,
        generatedKeys.privateKey
      );
      // Step 3: Validation
      if (decryptedData === plaintext) {
        console.log('✅ RSA Encryption and Decryption Successful!');
      } else {
        console.error('❌ Decrypted data does not match original plaintext!');
      }
    } catch (error) {
      console.error('⚠️ RSA Error:', error);
    }
  }

  async function handleAsyncRSAEncryption() {
    const plaintext = 'Hello, RSA Encryption!';
    const generatedKeys = generateRSAKeyPair();
    try {
      // Step 1: Encrypt the plaintext using the Public Key
      const encryptedData = await encryptAsyncRSA(
        plaintext,
        generatedKeys.publicKey
      );
      // Step 2: Decrypt the encrypted data using the Private Key
      const decryptedData = await decryptAsyncRSA(
        encryptedData,
        generatedKeys.privateKey
      );
      // Step 3: Validation
      if (decryptedData === plaintext) {
        console.log('✅ RSA Encryption and Decryption Successful!');
      } else {
        console.error('❌ Decrypted data does not match original plaintext!');
      }
    } catch (error) {
      console.error('⚠️ RSA Error:', error);
    }
  }

  const handleAESEncryption = () => {
    const sampleObject = {
      name: 'John Doe',
      age: 30,
      roles: ['admin', 'editor'],
    };
    try {
      const generatedKey = generateAESKey(256);
      const jsonString = JSON.stringify(sampleObject);
      const encryptedString = encryptAES(jsonString, generatedKey);

      // Decrypt and parse JSON
      const decryptedJsonString = decryptAES(encryptedString, generatedKey);
      const decryptedObject = JSON.parse(decryptedJsonString);
      console.log('Decrypted Object:', decryptedObject);
    } catch (err: unknown) {
      if (err instanceof Error) {
        let error = err.cause as EncryptionError;
        console.log('❌ Error:123', error.message);
      } else {
        console.log('❌ Unknown Error:', err);
      }
      setResult('An error occurred during encryption/decryption.');
    }
  };

  const handleAsyncESEncryption = async () => {
    const sampleObject = {
      name: 'John Doe',
      age: 30,
      roles: ['admin', 'editor'],
    };
    try {
      const generatedKey = generateAESKey(256);
      const jsonString = JSON.stringify(sampleObject);
      const encryptedString = await encryptAsyncAES(jsonString, generatedKey);
      console.log('encrypted Object:', encryptedString);

      // Decrypt and parse JSON
      const decryptedJsonString = await decryptAsyncAES(encryptedString, generatedKey);
      const decryptedObject = JSON.parse(decryptedJsonString);
      console.log('Decrypted Object:', decryptedObject);
    } catch (err: unknown) {
      if (err instanceof Error) {
        let error = err.cause as EncryptionError;
        console.log('❌ Error:123', error.message);
      } else {
        console.log('❌ Unknown Error:', err);
      }
      setResult('An error occurred during encryption/decryption.');
    }
  };

  const hashing = () => {
    try {
      console.log('--- Hashing ---');
      const sha256Hash = hashSHA256('Hello Hashing');
      console.log('SHA-256 Hash:', sha256Hash);

      const sha512Hash = hashSHA512('Hello Hashing');
      console.log('SHA-512 Hash:', sha512Hash);
    } catch (err) {
      console.log('error is', err);
    }
  };

  const hmac = () => {
    try {
      console.log('--- HMAC ---');
      const hmac = hmacSHA256('Hello HMAC', 'MyHMACKey');
      console.log('HMAC-SHA256:', hmac);
    } catch (err) {
      console.log('error is', err);
    }
  };

  const signData = () => {
    const keyPair = generateECDSAKeyPair();
    const data = 'Hello, ECDSA!';
    const signature = signDataECDSA(data, keyPair.privateKey);
    const isValid = verifySignatureECDSA(data, signature, keyPair.publicKey);

    console.log('Signature:', signature);
    console.log('Is Valid Signature:', isValid);
  };

  const base64 = ()=> {
    try {
      console.log('--- Base64 Encoding/Decoding ---');
      const base64Encoded = base64Encode('Hello Base64 Encoding');
      console.log('Base64 Encoded:', base64Encoded);

      const base64Decoded = base64Decode(base64Encoded);
      console.log('Base64 Decoded:', base64Decoded);
    } catch (err) {
      console.log('error is', err);
    }
  };

  const createRandomString = () => {
    try {
      console.log('--- Utilities ---');
      const randomString = generateRandomString(16);
      console.log('Random String:', randomString);
    } catch (err) {
      console.log('error is', err);
    }
  };

  return (
    <View style={{ flex: 1, alignItems: 'center', paddingTop: 80 }}>
      <Button title="Encrypt & Decrypt AES" onPress={handleAESEncryption} />
      <Button title="Async Encrypt & Decrypt AES" onPress={handleAsyncESEncryption} />


      <Button title="Encrypt & Decrypt RSA" onPress={handleRSAEncryption} />
      <Button title="Encrypt & Decrypt RSA" onPress={handleAsyncRSAEncryption} />


      <Button title="Hashing" onPress={hashing} />

      <Button title="HMAC" onPress={hmac} />

      <Button title="Base64 Encoding" onPress={base64} />

      <Button title="Generate random" onPress={createRandomString} />

      <Button title="Sign & Validate data" onPress={signData} />

      <Text style={styles.resultText}>{result}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  inputContainer: {
    marginVertical: 20,
    alignItems: 'center',
    width: '80%',
  },
  textInput: {
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 5,
    padding: 10,
    width: '100%',
    marginTop: 10,
  },
  resultText: {
    marginVertical: 20,
    textAlign: 'center',
    fontSize: 16,
  },
  counterWrapper: {
    height: 150,
    justifyContent: 'center',
    alignItems: 'center',
  },
  counterView: {
    width: 280,
    height: 140,
  },
  text: {
    marginBottom: 20,
    fontSize: 16,
  },
});
```

---

## 🐞 **7. Troubleshooting**

1. **Library Not Found:**  
   - Run `npx react-native link rn-encryption`.
   - Clean and rebuild the project.

2. **AES Key Size Error:**  
   - Ensure the AES key is **16, 24, or 32 characters**.

3. **RSA Key Parsing Issue:**  
   - Verify the RSA key is in **Base64-encoded PEM format**.

4. **Permission Issues:**  
   - Ensure native permissions are set correctly in **AndroidManifest.xml** or **iOS Podfile**.

---

## ✅ **8. Best Practices**

1. **Do Not Hardcode Keys:** Use `.env` or secure storage for keys.
2. **Handle Errors Gracefully:** Wrap calls in `try-catch` blocks.
3. **Validate Key Sizes:** Ensure AES and RSA keys meet size requirements.

---

## ❓ **9. FAQ**

**Q: Does the library support both Android and iOS?**  
A: Partially, `rn-encryption` fully supports ios and encryptAES & decryptAES for Android platforms.

**Q: Can I use the library in Expo?**  
A: Yes, if you're using **Expo Bare Workflow**.

**Q: How do I debug encryption issues?**  
A: Add console logs and verify that keys and data are correctly passed.

---

##  **10. Security Best Practices**

1. Use Strong Keys: Always use AES-256 for symmetric encryption and RSA-2048 for asymmetric encryption.
2. Key Storage: Store keys securely using Android Keystore and iOS Keychain.
3. Avoid Hardcoding Keys: Do not hardcode encryption keys directly in the app.

### 📚 **Encryption Mechanisms: Android (JCA) vs iOS (CryptoKit)**

| **Feature**                    | **Android (JCA)**                   | **iOS (CryptoKit)**              |
|--------------------------------|-------------------------------------|----------------------------------|
| **Symmetric Encryption**       | ✅ AES-256-GCM                      | ✅ AES-256-GCM                   |
| **Asymmetric Encryption**      | ✅ RSA-2048                         | ✅ RSA-2048                      |
| **Key Derivation**             | ✅ PBKDF2                           | ✅ PBKDF2 / ✅ HKDF              |
| **Hashing**                    | ✅ SHA-256, ✅ SHA-512              | ✅ SHA-256, ✅ SHA-512           |
| **Message Authentication**     | ✅ HMAC-SHA256                      | ✅ HMAC-SHA256                   |
| **Digital Signatures**         | ✅ ECDSA                            | ✅ ECDSA (via CryptoKit)         |
| **Key Management**             | ✅ Android Keystore                 | ✅ iOS Keychain                  |
| **Initialization Vector (IV)** | ✅ SecureRandom (12/16 Bytes)       | ✅ Randomized IV (12 Bytes)      |
| **Authentication Tag**         | ✅ Built-in (GCM Mode)              | ✅ Built-in (GCM Mode)           |
| **Error Handling**             | ✅ Strong Validation                | ✅ Strong Validation             |
| **Performance**                | ⚡ Optimized for Android             | ⚡ Optimized for iOS              |
| **Parallel Processing**        | ✅ Supported in GCM                 | ✅ Supported in GCM              |
| **Cryptographic Library**      | ✅ Java Cryptography (JCA)          | ✅ CryptoKit                     |

