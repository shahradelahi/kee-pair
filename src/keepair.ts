import * as crypto from 'node:crypto';
import type { KeyObject } from 'node:crypto';

import { ALGORITHM } from '@/constants';
import type { Algorithm, AlgorithmOptions, HashAlgorithm, KeyLike } from '@/typings';

export class KeePair<T extends Algorithm> {
  readonly #pubObject: KeyObject;
  readonly #privObject: KeyObject;

  readonly #pubBuf: Buffer;
  readonly #privBuf: Buffer;

  readonly algorithm: AlgorithmOptions<T>;

  get publicKey(): string {
    return this.#privBuf.toString('hex');
  }

  get privateKey(): string {
    return this.#privBuf.toString('hex');
  }

  constructor(publicKey: KeyLike, privateKey: KeyLike, algorithm: AlgorithmOptions<T>) {
    this.algorithm = algorithm;

    this.#pubBuf = typeof publicKey === 'string' ? Buffer.from(publicKey, 'hex') : publicKey;
    this.#privBuf = typeof privateKey === 'string' ? Buffer.from(privateKey, 'hex') : privateKey;

    this.#pubObject = crypto.createPublicKey({
      key: this.#pubBuf,
      type: this.algorithm.publicEncodingType,
      format: this.algorithm.publicEncodingFormat,
    });

    this.#privObject = crypto.createPrivateKey({
      key: this.#privBuf,
      type: this.algorithm.privateEncodingType,
      format: this.algorithm.privateEncodingFormat,
    });
  }

  static generate<T extends Algorithm>(algorithm: T, options: Partial<AlgorithmOptions<T>> = {}) {
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

  static fromPrivateKey<T extends Algorithm>(
    privateKey: KeyLike,
    algorithm: T,
    options: Partial<AlgorithmOptions<T>> = {}
  ) {
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

  sign(data: string, hashAlgorithm: HashAlgorithm): string {
    return crypto
      .createSign(hashAlgorithm.toLowerCase())
      .update(data)
      .sign(this.#privObject)
      .toString('hex');
  }

  verify(data: string, signature: string, hashAlgorithm: HashAlgorithm): boolean {
    return crypto
      .createVerify(hashAlgorithm.toLowerCase())
      .update(data)
      .verify(this.#pubObject, Buffer.from(signature, 'hex'));
  }
}

function findAlgorithmPreset<T extends Algorithm>(algorithm: T): AlgorithmOptions<Algorithm> {
  const algo = ALGORITHM.find((a) => a.sid === algorithm.toLowerCase());

  if (!algo) {
    throw new Error(`Algorithm "${algorithm}" is not supported.`);
  }

  return algo;
}
