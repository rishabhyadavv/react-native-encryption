# react-native-encryption

Encryption

## Installation

```sh
npm install rn-encryption
yarn add rn-encryption
```

## Usage


```js
import {encrypt, decrypt} from "rn-encryption"

// ...
const encryptionKey = "1234567890123456";

  const handleEncryption = async () => {
   
    try {
      const encrypted = await encrypt("sometexthere", encryptionKey);

      const decrypted = await decrypt(encrypted, encryptionKey);

      console.log(`Encrypted: ${encrypted}\nDecrypted: ${decrypted}`);
    } catch (err) {
       console.log('An error occurred during encryption/decryption.');
    }
  };
```

## I have just started to working on this repo
#I am creating encryption on native side i.e kotlin and objective-C using the turbo modules

## Contributing

See the [contributing guide](CONTRIBUTING.md) to learn how to contribute to the repository and the development workflow.

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
