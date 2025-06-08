# kee-pair

[![CI](https://github.com/shahradelahi/kee-pair/actions/workflows/ci.yml/badge.svg)](https://github.com/shahradelahi/kee-pair/actions/workflows/ci.yml)
[![NPM Version](https://img.shields.io/npm/v/kee-pair.svg)](https://www.npmjs.com/package/kee-pair)
[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat)](/LICENSE)
[![Install Size](https://packagephobia.com/badge?p=kee-pair)](https://packagephobia.com/result?p=kee-pair)

A TypeScript library for generating, managing, signing, and verifying asymmetric key pairs.

---

- [Installation](#-installation)
- [Usage](#-usage)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [License](#license)

## 📦 Installation

```bash
npm i kee-pair
```

## 📖 Usage

```typescript
import { KeePair } from 'kee-pair';

// Generate a new Secp256k1 key pair
const keyPair = KeePair.generate('secp256k1');

// Sign some data
const message = 'Hello, KeePair!';
const signature = keyPair.sign(message, 'sha256');

// Verify the signature
const isValid = keyPair.verify(message, signature, 'sha256');
console.log('Signature valid:', isValid);

// Restore key pair from an existing private key
const restored = KeePair.fromPrivateKey(keyPair.privateKey, 'secp256k1');

console.log(
  'Public keys match:',
  restored.publicKey.equals(keyPair.publicKey)
);
```

## 📚 Documentation

For all configuration options, please see [the API docs](https://www.jsdocs.io/package/kee-pair).

## 🤝 Contributing

Want to contribute? Awesome! To show your support is to star the project, or to raise issues on [GitHub](https://github.com/shahradelahi/kee-pair).

Thanks again for your support, it is much appreciated! 🙏

## License

[MIT](/LICENSE) © [Shahrad Elahi](https://github.com/shahradelahi) and [contributors](https://github.com/shahradelahi/kee-pair/graphs/contributors).
