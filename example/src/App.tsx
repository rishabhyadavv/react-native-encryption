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
} from 'rn-encryption';
interface EncryptionError {
  name: string;
  message: string;
}
export default function DashboardScreen() {
  const [result, setResult] = useState(''); // Encryption/Decryption result

  async function handleRSAEncryption() {
    const plaintext = 'Hello, RSA Encryption!';
    const generatedKeys = generateRSAKeyPair();
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

  const handleAESEncryption = async () => {
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

  const hashing = async () => {
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

  const hmac = async () => {
    try {
      console.log('--- HMAC ---');
      const hmac = hmacSHA256('Hello HMAC', 'MyHMACKey');
      console.log('HMAC-SHA256:', hmac);
    } catch (err) {
      console.log('error is', err);
    }
  };

  const signData = async () => {
    const keyPair = generateECDSAKeyPair();
    const data = 'Hello, ECDSA!';
    const signature = signDataECDSA(data, keyPair.privateKey);
    const isValid = verifySignatureECDSA(data, signature, keyPair.publicKey);

    console.log('Signature:', signature);
    console.log('Is Valid Signature:', isValid);
  };

  const base64 = async () => {
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

  const createRandomString = async () => {
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

      <Button title="Encrypt & Decrypt RSA" onPress={handleRSAEncryption} />

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
