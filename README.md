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
  generateRandomString,
  base64Encode,
  base64Decode,
} from 'rn-encryption';
```

Each method can be accessed directly without a default object wrapper.

---

## 📚 **5. API Overview**

### 🔒 **AES Encryption/Decryption**
- **`encryptAES(data: string, key: string): string`**  
- **`decryptAES(data: string, key: string): string`**

### 🔑 **RSA Encryption/Decryption**
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

---

## 🛠️ **6. Usage Examples**

### 🔒 **6.1 AES Encryption and Decryption**

```tsx
import { encryptAES, decryptAES } from 'rn-encryption';

const runAESExample = async () => {
  try {
    const plainText = "Hello, AES Encryption!";
    const key = "1234567890123456"; // Must be 16, 24, or 32 characters

    const encryptedText =  encryptAES(plainText, key);
    console.log("AES Encrypted Text:", encryptedText);

    const decryptedText =  decryptAES(encryptedText, key);
    console.log("AES Decrypted Text:", decryptedText);
  } catch (error) {
    console.error("AES Error:", error);
  }
};

runAESExample();
```

---

### 🔑 **6.2 RSA Encryption and Decryption**

```tsx
import { encryptRSA, decryptRSA } from 'rn-encryption';

const runRSAExample = async () => {
  try {
    const plainText = "Hello, RSA Encryption!";
    const publicKey = "YOUR_RSA_PUBLIC_KEY";
    const privateKey = "YOUR_RSA_PRIVATE_KEY";

    const encryptedText =  encryptRSA(plainText, publicKey);
    console.log("RSA Encrypted Text:", encryptedText);

    const decryptedText =  decryptRSA(encryptedText, privateKey);
    console.log("RSA Decrypted Text:", decryptedText);
  } catch (error) {
    console.error("RSA Error:", error);
  }
};

runRSAExample();
```

---

### 🛡️ **6.3 SHA Hashing**

```tsx
import { hashSHA256, hashSHA512 } from 'rn-encryption';

const runHashExample = async () => {
  const data = "Hash this string";

  const sha256 =  hashSHA256(data);
  console.log("SHA-256 Hash:", sha256);

  const sha512 =  hashSHA512(data);
  console.log("SHA-512 Hash:", sha512);
};

runHashExample();
```

---

### 📝 **6.4 HMAC-SHA256**

```tsx
import { hmacSHA256 } from 'rn-encryption';

const runHMACExample = async () => {
  const message = "Authenticate this";
  const secretKey = "SecretKey";

  const hmac =  hmacSHA256(message, secretKey);
  console.log("HMAC-SHA256:", hmac);
};

runHMACExample();
```

---

### 🎲 **6.5 Random String Generation**

```tsx
import { generateRandomString } from 'rn-encryption';

const runRandomStringExample = async () => {
  const randomString =  generateRandomString(16);
  console.log("Random String:", randomString);
};

runRandomStringExample();
```

---

### 📝 **6.6 Base64 Encoding/Decoding**

```tsx
import { base64Encode, base64Decode } from 'rn-encryption';

const runBase64Example = () => {
  const plainText = "Base64 this text";

  const encoded = base64Encode(plainText);
  console.log("Base64 Encoded:", encoded);

  const decoded = base64Decode(encoded);
  console.log("Base64 Decoded:", decoded);
};

runBase64Example();
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

