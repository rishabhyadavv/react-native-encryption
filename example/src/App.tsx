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
  decryptFile,
  generateHMACKey,
  signDataRSA,
  verifySignatureRSA,
  pbkdf2,
  getRandomBytes,
  encryptRSAOAEP,
  decryptRSAOAEP,
} from '../../src';
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

    console.log('ECDSA Signature:', signature);
    console.log('ECDSA Is Valid:', isValid);
  };

  const signDataRSAExample = () => {
    try {
      const keyPair = generateRSAKeyPair();
      const data = 'Hello, RSA Signing!';
      const signature = signDataRSA(data, keyPair.privateKey);
      const isValid = verifySignatureRSA(data, signature, keyPair.publicKey);
      console.log('RSA Signature:', signature.substring(0, 40) + '...');
      console.log('RSA Is Valid:', isValid);

      const isTampered = verifySignatureRSA(
        'tampered',
        signature,
        keyPair.publicKey
      );
      console.log('RSA Tampered rejected:', !isTampered);
    } catch (err) {
      console.log('RSA Sign Error:', err);
    }
  };

  const handlePBKDF2 = () => {
    try {
      const derivedKey = pbkdf2(
        'myPassword',
        'randomSalt',
        100000,
        32,
        'SHA-256'
      );
      console.log('PBKDF2 Derived Key (SHA-256):', derivedKey);

      const derivedKey512 = pbkdf2(
        'myPassword',
        'randomSalt',
        100000,
        32,
        'SHA-512'
      );
      console.log('PBKDF2 Derived Key (SHA-512):', derivedKey512);
    } catch (err) {
      console.log('PBKDF2 Error:', err);
    }
  };

  const handleRandomBytes = () => {
    try {
      const bytes16 = getRandomBytes(16);
      console.log('Random 16 bytes:', bytes16);

      const bytes32 = getRandomBytes(32);
      console.log('Random 32 bytes:', bytes32);
    } catch (err) {
      console.log('Random Bytes Error:', err);
    }
  };

  const handleRSAOAEP = () => {
    try {
      const keyPair = generateRSAKeyPair();
      const plaintext = 'Hello, RSA-OAEP!';

      const encrypted = encryptRSAOAEP(plaintext, keyPair.publicKey);
      console.log('RSA-OAEP Encrypted:', encrypted.substring(0, 40) + '...');

      const decrypted = decryptRSAOAEP(encrypted, keyPair.privateKey);
      console.log('RSA-OAEP Decrypted:', decrypted);
      console.log('RSA-OAEP Match:', decrypted === plaintext);
    } catch (err) {
      console.log('RSA-OAEP Error:', err);
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

  async function handleEncryptFileAES() {
    try {
      // Step 1: Write Sample Data to a File
      await RNFS.writeFile(
        inputPath,
        'This is a sensitive file content.',
        'utf8'
      );
      console.log(`File written at: ${inputPath}`);

      const generatedKey = generateAESKey(256);
      console.log('generatedKey ', generatedKey);

      // Step 2: Encrypt the File
      const encryptedFilePath = await encryptFile(
        inputPath,
        outputPath,
        generatedKey
      );
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

      <Button title="Encrypt & Decrypt File" onPress={handleEncryptFileAES} />

      <Button title="Encrypt & Decrypt RSA" onPress={handleRSAEncryption} />
      <Button
        title="Encrypt & Decrypt RSA"
        onPress={handleAsyncRSAEncryption}
      />

      <Button title="Hashing" onPress={hashing} />

      <Button title="HMAC" onPress={hmac} />

      <Button title="Base64 Encoding" onPress={base64} />

      <Button title="Generate random" onPress={createRandomString} />

      <Button title="ECDSA Sign & Verify" onPress={signData} />

      <Button title="RSA Sign & Verify" onPress={signDataRSAExample} />

      <Button title="PBKDF2 Key Derivation" onPress={handlePBKDF2} />

      <Button title="Secure Random Bytes" onPress={handleRandomBytes} />

      <Button title="RSA-OAEP Encrypt & Decrypt" onPress={handleRSAOAEP} />

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
