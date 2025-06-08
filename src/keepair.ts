import * as crypto from 'node:crypto';
import type { KeyObject } from 'node:crypto';

import { ALGORITHM } from '@/constants';
import type { Algorithm, AlgorithmOptions, HashAlgorithm, KeyLike } from '@/typings';

/**
 * Keystore for asymmetric key pairs, supporting key generation, signing, and verification.
 *
 * @example
 * ```ts
 * import { KeePair } from 'kee-pair';
 *
 * // Generate a new Secp256k1 key pair
 * const keyPair = KeePair.generate('secp256k1');
 *
 * // Sign some data
 * const message = 'Hello, World!';
 * const signature = keyPair.sign(message, 'sha256');
 *
 * // Verify the signature
 * const isValid = keyPair.verify(message, signature, 'sha256');
 * console.log('Signature valid:', isValid);
 * ```
 */
export class KeePair<T extends Algorithm> {
  readonly #pubObject: KeyObject;
  readonly #privObject: KeyObject;

  /**
   * DER or PEM encoded public key buffer.
   */
  readonly publicKey: Buffer;

  /**
   * DER or PEM encoded private key buffer.
   */
  readonly privateKey: Buffer;

  /**
   * Algorithm options including encoding types and formats.
   */
  readonly algorithm: AlgorithmOptions<T>;

  /**
   * Creates an instance of KeePair from given key material.
   *
   * @param publicKey - Public key in Buffer or hex string form.
   * @param privateKey - Private key in Buffer or hex string form.
   * @param algorithm - Algorithm options defining encoding and format.
   */
  constructor(publicKey: KeyLike, privateKey: KeyLike, algorithm: AlgorithmOptions<T>) {
    this.algorithm = algorithm;

    this.publicKey = typeof publicKey === 'string' ? Buffer.from(publicKey, 'hex') : publicKey;
    this.privateKey = typeof privateKey === 'string' ? Buffer.from(privateKey, 'hex') : privateKey;

    this.#pubObject = crypto.createPublicKey({
      key: this.publicKey,
      type: this.algorithm.publicEncodingType,
      format: this.algorithm.publicEncodingFormat,
    });

    this.#privObject = crypto.createPrivateKey({
      key: this.privateKey,
      type: this.algorithm.privateEncodingType,
      format: this.algorithm.privateEncodingFormat,
    });
  }

  /**
   * Generates a new asymmetric key pair for the specified algorithm.
   *
   * @param algorithm - The identifier of the algorithm to use (e.g., 'rsa', 'secp256k1').
   * @param options - Optional overrides for algorithm parameters.
   * @returns A new {@link KeePair} instance containing generated keys.
   *
   * @example
   * ```ts
   * const rsaPair = KeePair.generate('rsa', { modulusLength: 3072 });
   * console.log(rsaPair.publicKey.toString('hex'));
   * ```
   */
  static generate<T extends Algorithm>(
    algorithm: T,
    options: Partial<AlgorithmOptions<T>> = {}
  ): KeePair<T> {
    const presetOpts = findAlgorithmPreset(algorithm);
    const opts = { ...presetOpts, ...options } as AlgorithmOptions<T>;

    const { publicKey, privateKey } = crypto.generateKeyPairSync(presetOpts.name as any, opts);

    return new KeePair(
      publicKey.export({
        type: opts.publicEncodingType,
        format: opts.publicEncodingFormat,
      }),
      privateKey.export({
        type: opts.privateEncodingType,
        format: opts.privateEncodingFormat,
      }),
      opts
    ) as KeePair<T>;
  }

  /**
   * Reconstructs a key pair from an existing private key, deriving the public key.
   *
   * @param privateKey - Private key in Buffer or hex string form.
   * @param algorithm - The identifier of the algorithm used to generate the key.
   * @param options - Optional overrides for algorithm parameters.
   * @returns A new {@link KeePair} instance with the same key pair.
   *
   * @example
   * ```ts
   * const backupPrivate = existingPair.privateKey;
   * const restored = KeePair.fromPrivateKey(backupPrivate, 'secp256k1');
   * console.assert(
   *   restored.publicKey.equals(existingPair.publicKey)
   * );
   * ```
   */
  static fromPrivateKey<T extends Algorithm>(
    privateKey: KeyLike,
    algorithm: T,
    options: Partial<AlgorithmOptions<T>> = {}
  ): KeePair<T> {
    const presetOpt = findAlgorithmPreset(algorithm);
    const opts = { ...presetOpt, ...options } as AlgorithmOptions<T>;

    const key = crypto.createPrivateKey({
      key: typeof privateKey === 'string' ? Buffer.from(privateKey, 'hex') : privateKey,
      type: opts.privateEncodingType,
      format: opts.privateEncodingFormat,
    });

    const publicKey = crypto.createPublicKey(key).export({
      type: opts.publicEncodingType,
      format: opts.publicEncodingFormat,
    });

    return new KeePair(publicKey, privateKey, opts) as KeePair<T>;
  }

  /**
   * Signs the provided data with the private key using the specified hash algorithm.
   *
   * @param data - The string data to sign.
   * @param hashAlgorithm - Hash algorithm identifier (e.g., 'sha256').
   * @returns A Buffer containing the signature.
   *
   * @example
   * ```ts
   * const sig = keyPair.sign('payload', 'sha512');
   * ```
   */
  sign(data: string, hashAlgorithm: HashAlgorithm): Buffer {
    return crypto.createSign(hashAlgorithm.toLowerCase()).update(data).sign(this.#privObject);
  }

  /**
   * Verifies a signature against the provided data and public key.
   *
   * @param data - The original data that was signed.
   * @param signature - The signature Buffer to verify.
   * @param hashAlgorithm - Hash algorithm identifier used during signing.
   * @returns True if the signature is valid, false otherwise.
   *
   * @example
   * ```ts
   * const valid = keyPair.verify('payload', signature, 'sha512');
   * ```
   */
  verify(data: string, signature: Buffer, hashAlgorithm: HashAlgorithm): boolean {
    return crypto
      .createVerify(hashAlgorithm.toLowerCase())
      .update(data)
      .verify(this.#pubObject, signature);
  }
}

/**
 * Retrieves preset algorithm options based on a string identifier.
 *
 * @internal
 * @param algorithm - The algorithm identifier (case-insensitive).
 * @throws Will throw an error if the algorithm is not supported.
 */
function findAlgorithmPreset<T extends Algorithm>(algorithm: T): AlgorithmOptions<Algorithm> {
  const algo = ALGORITHM.find((a) => a.sid === algorithm.toLowerCase());

  if (!algo) {
    throw new Error(`Algorithm "${algorithm}" is not supported.`);
  }

  return algo;
}
