import {describe, expect, test} from "@jest/globals";
import {KeePair} from "../index";

describe('KeePair', () => {

   test('Generate a KeePair with Secp256k1', async () => {

      const pair = await KeePair.generate("secp256k1");

      expect(pair).toBeDefined();

      expect(pair.privateKey).toBeDefined();
      expect(pair.privateKey.length).toBe(236);

      expect(pair.publicKey).toBeDefined();
      expect(pair.publicKey.length).toBe(176);
   });

   test('Regenerate a Public Key from a Private Key', async () => {

      const pair = await KeePair.generate("secp256k1");

      const pubKey = await KeePair.fromPrivateKey(pair.privateKey, "secp256k1");

      expect(pair.publicKey).toBe(pubKey.publicKey);
   });

   test('Sign a Message', async () => {

      const pair = await KeePair.generate("secp256k1");

      const message = "Hello World!";

      const signature = pair.sign(message, "sha256");

      expect(signature).toBeDefined();
      expect(signature.length).toBeGreaterThanOrEqual(140);
   });

   test('Verify a Signature', async () => {

      const pair = await KeePair.generate("secp256k1");

      const message = "Hello World!";

      const signature = pair.sign(message, "sha256");

      const verified = pair.verify(message, signature, "sha256");

      expect(verified).toBe(true);
   });

});
