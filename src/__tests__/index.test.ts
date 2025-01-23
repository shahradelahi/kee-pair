import { describe, expect, test } from 'vitest';

import { KeePair } from '@/index';

describe('KeePair', () => {
  test('Generate a KeePair with Secp256k1', () => {
    const pair = KeePair.generate('secp256k1');

    expect(pair).toBeDefined();

    expect(pair.privateKey).toBeDefined();
    expect(pair.privateKey.length).toBe(236);

    expect(pair.publicKey).toBeDefined();
    expect(pair.publicKey.length).toBe(236);
  });

  test('Regenerate a Public Key from a Private Key', () => {
    const pair = KeePair.generate('secp256k1');

    const pubKey = KeePair.fromPrivateKey(pair.privateKey, 'secp256k1');

    expect(pair.publicKey).toBe(pubKey.publicKey);
  });

  test('Sign a Message', () => {
    const pair = KeePair.generate('secp256k1');

    const message = 'Hello World!';

    const signature = pair.sign(message, 'sha256');

    expect(signature).toBeDefined();
    expect(signature.byteLength).toBeGreaterThanOrEqual(70);
  });

  test('Verify a Signature', () => {
    const pair = KeePair.generate('secp256k1');

    const message = 'Hello World!';

    const signature = pair.sign(message, 'sha256');

    const verified = pair.verify(message, signature, 'sha256');

    expect(verified).toBe(true);
  });
});
