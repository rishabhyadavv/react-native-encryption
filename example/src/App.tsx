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
      const hmachash = hmacSHA256('Hello HMAC', 'MyHMACKey');
      console.log('HMAC-SHA256:', hmachash);
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
