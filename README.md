# 📚 **React Native Integration Guide for `rn-encryption` Library**

This guide explains how to directly access methods from the `rn-encryption` library in a **React Native project**, including usage examples for AES, RSA, Hashing, HMAC, Random String, and Base64 utilities.
- **Mobile (iOS & Android): Utilizes native implementations through JSI (JavaScript Interface) via Turbo Modules for encryption.**
- **Web: Leverages crypto.subtle for encryption functionality. https://www.npmjs.com/package/web-secure-encryption is being used to support encryption for web.**

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
expo install rn-encryption

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
  signDataRSA,
  verifySignatureRSA,
  encryptAsyncAES,
  decryptAsyncAES,
  encryptAsyncRSA,
  decryptAsyncRSA,
  encryptFile,
  decryptFile,
  pbkdf2,
  getRandomBytes,
  encryptRSAOAEP,
  decryptRSAOAEP,
} from 'rn-encryption';
```

- **Each method can be accessed directly without a default object wrapper.**
- **Please note that encryptFile/decryptFile methods are not available for web yet.**
- **All web methods have promises while few native methods can be called without promises.**

---

## 📚 **5. API Overview**

### 🔒 **AES Encryption/Decryption**
- **`generateAESKey(keySize: number): string`**  
- **`encryptAES(data: string, key: string): string`**  
- **`decryptAES(data: string, key: string): string`**

### 🔑 **RSA Encryption/Decryption**
- **`generateRSAKeyPair(): keypair`**  
- **`getPublicRSAkey(privateKey: string): string`**  
- **`encryptRSA(data: string, publicKey: string): string`** — PKCS#1 v1.5 padding  
- **`decryptRSA(data: string, privateKey: string): string`** — PKCS#1 v1.5 padding

### 🔒 **RSA-OAEP Encryption (Recommended)**
- **`encryptRSAOAEP(data: string, publicKey: string): string`** — OAEP + SHA-256 padding  
- **`decryptRSAOAEP(data: string, privateKey: string): string`** — OAEP + SHA-256 padding

### ✍️ **RSA Digital Signatures**
- **`signDataRSA(data: string, privateKey: string): string`** — PKCS#1 v1.5 + SHA-256  
- **`verifySignatureRSA(data: string, signatureBase64: string, publicKey: string): boolean`**

### 🛡️ **SHA Hashing**
- **`hashSHA256(input: string): string`**  
- **`hashSHA512(input: string): string`**

### 📝 **HMAC**
- **`generateHMACKey(keySize: number): string`**  
- **`hmacSHA256(data: string, key: string): string`**  
- **`hmacSHA512(data: string, key: string): string`**

### 🔑 **PBKDF2 Key Derivation**
- **`pbkdf2(password: string, salt: string, iterations: number, keyLength: number, hash: string): string`**

### 🎲 **Random Generation**
- **`generateRandomString(input: number): string`**  
- **`getRandomBytes(size: number): string`** — Returns Base64-encoded secure random bytes

### 📝 **Base64 Encoding/Decoding**
- **`base64Encode(input: string): string`**  
- **`base64Decode(input: string): string`**

### 🔒 **ECDSA Digital Signatures**
- **`generateECDSAKeyPair(): keypair`**  
- **`getPublicECDSAKey(privateKey: string): string`**  
- **`signDataECDSA(data: string, key: string): string`**  
- **`verifySignatureECDSA(data: string, signatureBase64: string, key: string): boolean`**

### 🔒 **Asynchronous Methods**
- **`encryptAsyncAES(data: string, key: string): Promise<string>`**
- **`decryptAsyncAES(data: string, key: string): Promise<string>`**
- **`encryptAsyncRSA(data: string, key: string): Promise<string>`**
- **`decryptAsyncRSA(data: string, key: string): Promise<string>`**
- **`encryptFile(inputPath: string, outputPath: string, key: string): Promise<string>`**
- **`decryptFile(inputPath: string, key: string): Promise<string>`**
---

## 🛠️ **6.Native Usage Examples**

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
  decryptAsyncRSA,
  encryptFile,
  decryptFile
} from 'rn-encryption';
import RNFS from 'react-native-fs';

interface EncryptionError {
  name: string;
  message: string;
}
export default function DashboardScreen() {
  const [result, setResult] = useState(''); // Encryption/Decryption result

  const inputPath = `${RNFS.DocumentDirectoryPath}/data.txt`;
const outputPath = `${RNFS.DocumentDirectoryPath}/data.enc`;
const decryptedPath = `${RNFS.DocumentDirectoryPath}/data-decrypted.txt`;

  function handleRSAEncryption() {
    const plaintext = 'Hello, RSA Encryption!';
    const generatedKeys = generateRSAKeyPair();
    try {
      // Step 1: Encrypt the plaintext using the Public Key
      const encryptedData = encryptRSA(plaintext, generatedKeys.publicKey);
      // Step 2: Decrypt the encrypted data using the Private Key
      const decryptedData = decryptRSA(encryptedData, generatedKeys.privateKey);
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
      const decryptedJsonString = await decryptAsyncAES(
        encryptedString,
        generatedKey
      );
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
      const hmackey = generateHMACKey(256);
      const hmachash = hmacSHA256('Hello HMAC', hmackey);

      const hmackey512 = generateHMACKey(512);
      const hmachash512 = hmacSHA256('Hello HMAC', hmackey512);
      console.log('HMAC-SHA256:', hmachash, hmachash512);
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

  const base64 = () => {
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

  async function handleEncryptFileAES() {
    try {
      // Step 1: Write Sample Data to a File
      await RNFS.writeFile(inputPath, 'This is a sensitive file content.', 'utf8');
      console.log(`File written at: ${inputPath}`);

      const generatedKey = generateAESKey(256);
      console.log('generatedKey ', generatedKey);

  
      // Step 2: Encrypt the File
      const encryptedFilePath = await encryptFile(inputPath, outputPath, generatedKey);
      console.log('Encrypted File Path:', encryptedFilePath);
  
      // Step 3: Verify Encrypted File
      const encryptedFileExists = await RNFS.exists(outputPath);
      console.log('Encrypted File Exists:', encryptedFileExists);

      const decryptedContent = await decryptFile(outputPath, generatedKey);
      console.log('Decrypted File Content:', decryptedContent);
  
      // Step 5: Write Decrypted Content to a New File
      await RNFS.writeFile(decryptedPath, decryptedContent, 'utf8');
      console.log(`Decrypted file saved at: ${decryptedPath}`);
    } catch (error) {
      console.error('Encryption Error:', error);
    }
  }


  return (
    <View style={{ flex: 1, alignItems: 'center', paddingTop: 80 }}>
      <Button title="Encrypt & Decrypt AES" onPress={handleAESEncryption} />
      <Button
        title="Async Encrypt & Decrypt AES"
        onPress={handleAsyncESEncryption}
      />

<Button
        title="Encrypt & Decrypt File"
        onPress={handleEncryptFileAES}
      />

      <Button title="Encrypt & Decrypt RSA" onPress={handleRSAEncryption} />
      <Button
        title="Encrypt & Decrypt RSA"
        onPress={handleAsyncRSAEncryption}
      />

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

## 🛠️ **6b. New Features Usage Examples**

### RSA Digital Signatures
```tsx
import { generateRSAKeyPair, signDataRSA, verifySignatureRSA } from 'rn-encryption';

const keyPair = generateRSAKeyPair();
const data = 'Important document content';
const signature = signDataRSA(data, keyPair.privateKey);
const isValid = verifySignatureRSA(data, signature, keyPair.publicKey);
console.log('Signature valid:', isValid); // true
```

### PBKDF2 Key Derivation
```tsx
import { pbkdf2, encryptAES, decryptAES } from 'rn-encryption';

// Derive an encryption key from a password
const derivedKey = pbkdf2(
  'user-password',    // password
  'random-salt-here', // salt (should be random per user)
  100000,             // iterations (higher = more secure but slower)
  32,                 // key length in bytes (32 = 256 bits for AES-256)
  'SHA-256'           // hash algorithm: 'SHA-256' or 'SHA-512'
);

// Use the derived key for AES encryption
const encrypted = encryptAES('sensitive data', derivedKey);
const decrypted = decryptAES(encrypted, derivedKey);
```

### Secure Random Bytes
```tsx
import { getRandomBytes } from 'rn-encryption';

// Generate 32 bytes of cryptographically secure random data (Base64-encoded)
const randomBytes = getRandomBytes(32);
console.log('Random bytes:', randomBytes);

// Useful for generating salts, nonces, or tokens
const salt = getRandomBytes(16);
```

### RSA-OAEP Encryption (More Secure)
```tsx
import { generateRSAKeyPair, encryptRSAOAEP, decryptRSAOAEP } from 'rn-encryption';

// RSA-OAEP is recommended over PKCS#1 v1.5 for new applications
const keyPair = generateRSAKeyPair();
const encrypted = encryptRSAOAEP('sensitive data', keyPair.publicKey);
const decrypted = decryptRSAOAEP(encrypted, keyPair.privateKey);
console.log('Decrypted:', decrypted); // 'sensitive data'
```

---

## 🛠️ **7.Web Usage Examples**
```tsx
import { View, Text,  StyleSheet, Button } from 'react-native';
import  { generateAESKey, encryptAES, decryptAES, generateRSAKeyPair, encryptRSA, decryptRSA, generateECDSAKeyPair, signDataECDSA, verifySignatureECDSA, generateHMACKey, hmacSHA256, hmacSHA512, hashSHA256, hashSHA512, generateRandomString, base64Decode, base64Encode } from 'rn-encryption';

export default function HomeScreen() {

  const handleAESEncryption = async () => {
    const sampleObject = {
      name: 'John Doe',
      age: 30,
      roles: ['admin', 'editor'],
    };
    try {
      const generatedKey = await generateAESKey();
      const jsonString = JSON.stringify(sampleObject);
      const encryptedString = await encryptAES(jsonString, generatedKey);

      // Decrypt and parse JSON
      const decryptedJsonString = await decryptAES(encryptedString, generatedKey);
      const decryptedObject = JSON.parse(decryptedJsonString);
      console.log('Decrypted Object:', generatedKey, );
    } catch (err: unknown) {
     
        console.log('❌ Error:123', err);
     
    }
  };

  async function handleAsyncRSAEncryption() {
    const plaintext = 'Hello, RSA Encryption!';
    const generatedKeys = await generateRSAKeyPair();
    try {
      // Step 1: Encrypt the plaintext using the Public Key
      const encryptedData = await encryptRSA(
        plaintext,
        generatedKeys.publicKey
      );
      // Step 2: Decrypt the encrypted data using the Private Key
      const decryptedData = await decryptRSA(
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

  const hashing = async () => {
    try {
      console.log('--- Hashing ---');
      const sha256Hash = await hashSHA256('Hello Hashing');
      console.log('SHA-256 Hash:', sha256Hash);

      const sha512Hash = await hashSHA512('Hello Hashing');
      console.log('SHA-512 Hash:', sha512Hash);
    } catch (err) {
      console.log('error is', err);
    }
  };

  const hmac = async() => {
    try {
      const macKey = await generateHMACKey(256)
      console.log('--- HMAC ---',macKey);

      const hmachash = await hmacSHA256('Hello HMAC', macKey);
      console.log('HMAC-SHA256:', hmachash);
    } catch (err) {
      console.log('error is', err);
    }
  };

  const base64 = async () => {
    try {
      console.log('--- Base64 Encoding/Decoding ---');
      const base64Encoded = await base64Encode('Hello Base64 Encoding');
      console.log('Base64 Encoded:', base64Encoded);

      const base64Decoded =await base64Decode(base64Encoded);
      console.log('Base64 Decoded:', base64Decoded);
    } catch (err) {
      console.log('error is', err);
    }
  };

  const createRandomString = async () => {
    try {
      console.log('--- Utilities ---');
      const randomString = await generateRandomString(16);
      console.log('Random String:', randomString);
    } catch (err) {
      console.log('error is', err);
    }
  };

  const signData = async () => {
    const keyPair = await generateECDSAKeyPair();
    const data = 'Hello, ECDSA!';
    const signature = await signDataECDSA(data, keyPair.privateKey);
    const isValid = await verifySignatureECDSA(data, signature, keyPair.publicKey);

    console.log('Signature:', signature);
    console.log('Is Valid Signature:', isValid);
  };

  return (
    <View style={styles.container}>
      <Text style={styles.header}>Dynamic Routing Example</Text>
      <Button title="Encrypt & Decrypt AES" onPress={handleAESEncryption} />
      <Button title="Encrypt & Decrypt RSA" onPress={handleAsyncRSAEncryption} />
      <Button title="Sign data" onPress={signData} />
      <Button title="Hashing" onPress={hashing} />
      <Button title="HMAC" onPress={hmac} />
      <Button title="Base64 Encoding" onPress={base64} />
      <Button title="Generate random" onPress={createRandomString} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 16,
    justifyContent: 'center',
    backgroundColor: '#f4f4f4',
  },
  header: {
    fontSize: 20,
    fontWeight: 'bold',
    marginBottom: 16,
    textAlign: 'center',
  },
  item: {
    padding: 16,
    marginVertical: 8,
    backgroundColor: '#fff',
    borderRadius: 8,
    shadowColor: '#000',
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 2,
  },
  text: {
    fontSize: 16,
  },
});
```

# **Keychain Integration for keys**
 - **Key Storage:** It is recommended to save encryption keys in Keychain (iOS) and Keystore (Android) for enhanced security.
 - **Example Implementation:** You can refer to an example in this repository for guidance.
 - **Customization:** The provided example serves as a sample implementation and can be modified according to specific requirements.

---

## 🐞 **8. Troubleshooting**

1. **Library Not Found:**  
   - Run `npx react-native link rn-encryption`.
   - Clean and rebuild the project.

2. **AES Key Size Error:**  
   - Ensure the AES key is **128, 192, or 256 bits** (use `generateAESKey(256)` to create one).

3. **RSA Key Parsing Issue:**  
   - Verify the RSA key is in **Base64-encoded DER format** (as returned by `generateRSAKeyPair()`).

4. **Permission Issues:**  
   - Ensure native permissions are set correctly in **AndroidManifest.xml** or **iOS Podfile**.

---

## ✅ **9. Best Practices**

1. **Do Not Hardcode Keys:** Use `.env` or secure storage for keys.
2. **Handle Errors Gracefully:** Wrap calls in `try-catch` blocks.
3. **Validate Key Sizes:** Ensure AES and RSA keys meet size requirements.
4. **Use RSA-OAEP over PKCS#1 v1.5:** For new RSA encryption, prefer `encryptRSAOAEP`/`decryptRSAOAEP` as PKCS#1 v1.5 is vulnerable to padding oracle attacks.
5. **Use PBKDF2 for password-based keys:** Never use passwords directly as encryption keys. Use `pbkdf2()` with a random salt and high iteration count (100,000+).
6. **Generate random salts:** Use `getRandomBytes()` to generate unique salts for PBKDF2 and other operations.

---

## ❓ **10. FAQ**

**Q: Does the library support both Android and iOS?**  
A: Yes, `rn-encryption` fully supports both iOS and Android platforms with AES, RSA, ECDSA, SHA hashing, HMAC, Base64, and file encryption.

**Q: Can I use the library in Expo?**  
A: Yes, if you're using **Expo Bare Workflow**.

**Q: How do I debug encryption issues?**  
A: Add console logs and verify that keys and data are correctly passed.

---

##  **11. Security Best Practices**

1. Use Strong Keys: Always use AES-256 for symmetric encryption and RSA-2048 for asymmetric encryption.
2. Key Storage: Store keys securely using Android Keystore and iOS Keychain.
3. Avoid Hardcoding Keys: Do not hardcode encryption keys directly in the app.

### 📚 **Encryption Mechanisms: Android (JCA) vs iOS (CryptoKit)**

| **Feature**                    | **Android (JCA)**                   | **iOS (CryptoKit)**              |
|--------------------------------|-------------------------------------|----------------------------------|
| **Symmetric Encryption**       | ✅ AES-256-GCM                      | ✅ AES-256-GCM                   |
| **Asymmetric Encryption**      | ✅ RSA-2048                         | ✅ RSA-2048                      |
| **Hashing**                    | ✅ SHA-256, ✅ SHA-512              | ✅ SHA-256, ✅ SHA-512           |
| **Message Authentication**     | ✅ HMAC-SHA256, ✅ HMAC-SHA512      | ✅ HMAC-SHA256, ✅ HMAC-SHA512   |
| **Digital Signatures**         | ✅ ECDSA, ✅ RSA (SHA-256)          | ✅ ECDSA, ✅ RSA (SHA-256)       |
| **Key Derivation**             | ✅ PBKDF2 (SHA-256/SHA-512)         | ✅ PBKDF2 (SHA-256/SHA-512)      |
| **RSA-OAEP**                   | ✅ OAEP + SHA-256                   | ✅ OAEP + SHA-256                |
| **Secure Random**              | ✅ SecureRandom                     | ✅ SecRandomCopyBytes            |
| **Key Management**             | ✅ Android Keystore                 | ✅ iOS Keychain                  |
| **Initialization Vector (IV)** | ✅ SecureRandom (12/16 Bytes)       | ✅ Randomized IV (12 Bytes)      |
| **Authentication Tag**         | ✅ Built-in (GCM Mode)              | ✅ Built-in (GCM Mode)           |
| **Error Handling**             | ✅ Strong Validation                | ✅ Strong Validation             |
| **Performance**                | ⚡ Optimized for Android             | ⚡ Optimized for iOS              |
| **Parallel Processing**        | ✅ Supported in GCM                 | ✅ Supported in GCM              |
| **Cryptographic Library**      | ✅ Java Cryptography (JCA)          | ✅ CryptoKit                     |

