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
  signDataECDSA,
  verifySignatureECDSA,
  encryptAsyncAES,
  decryptAsyncAES,
  encryptAsyncRSA,
  decryptAsyncRSA,
  encryptFile,
  decryptFile,
  getPublicRSAkey,
  getPublicECDSAKey,
} from '../../src';
import RNFS from 'react-native-fs';
import KeychainManager, { STORAGE_TYPE } from './KeychainManager';

interface EncryptionError {
  name: string;
  message: string;
}
export default function DashboardScreen() {
  const [result, setResult] = useState(''); // Encryption/Decryption result

  const inputPath = `${RNFS.DocumentDirectoryPath}/data.txt`;
  const outputPath = `${RNFS.DocumentDirectoryPath}/data.enc`;
  const decryptedPath = `${RNFS.DocumentDirectoryPath}/data-decrypted.txt`;

  // ------------------------------------------------------------------
  // ✅ AES Key Management with Keychain
  // ------------------------------------------------------------------

  const handleAESEncryption = async () => {
    try {
      let aesKey = await KeychainManager.getAESKey();

      if (!aesKey) {
        aesKey = await KeychainManager.generateAndStoreAESKey(
          256,
          STORAGE_TYPE.AES_GCM_NO_AUTH
        );
        console.log('Generated and stored AES Key:', aesKey);
      } else {
        console.log('Retrieved AES Key from Keychain:', aesKey);
      }

      const sampleData = 'Sensitive AES Data';
      const encryptedData = encryptAES(sampleData, aesKey);
      const decryptedData = decryptAES(encryptedData, aesKey);

      console.log('AES Encrypted Data:', encryptedData);
      console.log('AES Decrypted Data:', decryptedData);

      setResult(`AES Decrypted: ${decryptedData}`);
    } catch (error) {
      console.error('AES Key Management Error:', error);
      setResult('AES Key Management Failed');
    }
  };

  const handleAsyncESEncryption = async () => {
    const sampleObject = {
      name: 'John Doe',
      age: 30,
      roles: ['admin', 'editor'],
    };

    try {
      let aesKey = await KeychainManager.getAESKey();

      if (!aesKey) {
        aesKey = await KeychainManager.generateAndStoreAESKey(
          256,
          STORAGE_TYPE.AES_GCM_NO_AUTH
        );
        console.log('Generated and stored AES Key:', aesKey);
      } else {
        console.log('Retrieved AES Key from Keychain:', aesKey);
      }

      const jsonString = JSON.stringify(sampleObject);
      const encryptedData = await encryptAsyncAES(jsonString, aesKey);
      const decryptedData = await decryptAsyncAES(encryptedData, aesKey);
      const decryptedObject = JSON.parse(decryptedData);

      console.log('AES Encrypted Data:', encryptedData);
      console.log('AES Decrypted Data:', decryptedObject);

      setResult(`AES Decrypted: ${decryptedData}`);
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

  // ------------------------------------------------------------------
  // ✅ RSA Key Management with Keychain
  // ------------------------------------------------------------------

  const handleRSAEncryption = async () => {
    try {
      let rsaPrivateKey = await KeychainManager.getRSAPrivateKey();
      let rsaPublicKeKey = '';

      if (!rsaPrivateKey) {
        const { publicKey, privateKey } =
          await KeychainManager.generateAndStoreRSAKeyPair(STORAGE_TYPE.RSA);
        console.log('Generated RSA Public Key:', publicKey);
        console.log('Stored RSA Private Key in Keychain:', privateKey);
        rsaPrivateKey = privateKey;
        rsaPublicKeKey = publicKey;
      } else {
        rsaPublicKeKey = getPublicRSAkey(rsaPrivateKey);
        console.log('Retrieved RSA Private Key from Keychain:', rsaPublicKeKey);
      }

      const sampleData = 'Sensitive RSA Data';
      const encryptedData = encryptRSA(sampleData, rsaPublicKeKey);
      const decryptedData = decryptRSA(encryptedData, rsaPrivateKey);

      // console.log('RSA Encrypted Data:', encryptedData);
      // console.log('RSA Decrypted Data:', decryptedData);

      setResult(`RSA Decrypted: ${decryptedData}`);
    } catch (error) {
      console.error('RSA Key Management Error:', error);
      setResult('RSA Key Management Failed');
    }
  };

  async function handleAsyncRSAEncryption() {
    try {
      let rsaPrivateKey = await KeychainManager.getRSAPrivateKey();
      let rsaPublicKeKey = '';

      if (!rsaPrivateKey) {
        const { publicKey, privateKey } =
          await KeychainManager.generateAndStoreRSAKeyPair(STORAGE_TYPE.RSA);
        console.log('Generated RSA Public Key:', publicKey);
        console.log('Stored RSA Private Key in Keychain:', privateKey);
        rsaPrivateKey = privateKey;
        rsaPublicKeKey = publicKey;
      } else {
        rsaPublicKeKey = getPublicRSAkey(rsaPrivateKey);
        console.log('Retrieved RSA Private Key from Keychain:', rsaPublicKeKey);
      }

      const sampleData = 'Sensitive RSA Data';
      const encryptedData = await encryptAsyncRSA(sampleData, rsaPublicKeKey);
      const decryptedData = await decryptAsyncRSA(encryptedData, rsaPrivateKey);

      // console.log('RSA Encrypted Data:', encryptedData);
      // console.log('RSA Decrypted Data:', decryptedData);

      setResult(`RSA Decrypted: ${decryptedData}`);
    } catch (error) {
      console.error('RSA Key Management Error:', error);
      setResult('RSA Key Management Failed');
    }
  }

  // ------------------------------------------------------------------
  // ✅ HMAC Key Management with Keychain
  // ------------------------------------------------------------------

  const handleHMACKeyHashing = async () => {
    try {
      let hmacKey = await KeychainManager.getHMACKey();

      if (!hmacKey) {
        hmacKey = await KeychainManager.generateAndStoreHMACKey(
          256,
          STORAGE_TYPE.AES_GCM_NO_AUTH
        );
        console.log('Generated and stored HMAC Key:', hmacKey);
      } else {
        console.log('Retrieved HMAC Key from Keychain:', hmacKey);
      }

      const hmacResult = hmacSHA256('Sensitive HMAC Data', hmacKey);
      console.log('HMAC Result:', hmacResult);

      setResult(`HMAC Result: ${hmacResult}`);
    } catch (error) {
      console.error('HMAC Key Management Error:', error);
      setResult('HMAC Key Management Failed');
    }
  };

  // ------------------------------------------------------------------
  // ✅ File Encryption with AES Key
  // ------------------------------------------------------------------

  const handleEncryptFileAES = async () => {
    try {
      let aesKey = await KeychainManager.getAESKey();

      if (!aesKey) {
        aesKey = await KeychainManager.generateAndStoreAESKey(
          256,
          STORAGE_TYPE.AES_GCM_NO_AUTH
        );
        console.log('Generated and stored AES Key:', aesKey);
      }

      await RNFS.writeFile(
        inputPath,
        'This is a sensitive file content.',
        'utf8'
      );
      console.log(`File written at: ${inputPath}`);

      const encryptedFilePath = await encryptFile(
        inputPath,
        outputPath,
        aesKey
      );
      console.log('Encrypted File Path:', encryptedFilePath);

      const decryptedContent = await decryptFile(outputPath, aesKey);
      console.log('Decrypted File Content:', decryptedContent);

      await RNFS.writeFile(decryptedPath, decryptedContent, 'utf8');
      console.log(`Decrypted file saved at: ${decryptedPath}`);

      setResult('File encryption and decryption successful!');
    } catch (error) {
      console.error('File Encryption Error:', error);
      setResult('File Encryption Failed');
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

  const signDataKeychain = async () => {
    try {
      let ecdaPrivateKey = await KeychainManager.getECDSAPrivateKey();
      let ecdaPublicKeKey = '';

      if (!ecdaPrivateKey) {
        const { publicKey, privateKey } =
          await KeychainManager.generateAndStoreECDSAKeyPair(STORAGE_TYPE.RSA);
        console.log('Generated RSA Public Key:', publicKey);
        console.log('Stored RSA Private Key in Keychain:', privateKey);
        ecdaPrivateKey = privateKey;
        ecdaPublicKeKey = publicKey;
      } else {
        ecdaPublicKeKey = getPublicECDSAKey(ecdaPrivateKey);
        console.log('Retrieved RSA Private Key from Keychain:', ecdaPrivateKey);
      }
      const data = 'Hello, ECDSA!';
      const signature = signDataECDSA(data, ecdaPrivateKey);
      const isValid = verifySignatureECDSA(data, signature, ecdaPublicKeKey);

      console.log('Signature:', signature);
      console.log('Is Valid Signature:', isValid);
    } catch (err) {
      console.log('error is', err);
    }
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

  return (
    <View style={{ flex: 1, alignItems: 'center', paddingTop: 80 }}>
      <Button title="Encrypt & Decrypt AES" onPress={handleAESEncryption} />
      <Button
        title="Async Encrypt & Decrypt AES"
        onPress={handleAsyncESEncryption}
      />

      <Button title="Encrypt & Decrypt File" onPress={handleEncryptFileAES} />

      <Button title="Encrypt & Decrypt RSA" onPress={handleRSAEncryption} />
      <Button
        title="Encrypt & Decrypt RSA"
        onPress={handleAsyncRSAEncryption}
      />

      <Button title="Hashing" onPress={hashing} />

      <Button title="HMAC" onPress={handleHMACKeyHashing} />

      <Button title="Base64 Encoding" onPress={base64} />

      <Button title="Generate random" onPress={createRandomString} />

      <Button title="Sign & Validate data" onPress={signDataKeychain} />

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
