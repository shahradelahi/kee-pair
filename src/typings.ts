import { ALGORITHM } from '@/constants';

export type HashAlgorithm = 'sha1' | 'sha256' | 'sha384' | 'sha512' | 'md5' | 'md5-sha1' | string;

export type Algorithm = (typeof ALGORITHM)[number]['sid'];

export type AlgorithmOptions<T extends Algorithm> = (typeof ALGORITHM)[number] & {
  sid: T;
};

export type KeyLike = Buffer | string;
