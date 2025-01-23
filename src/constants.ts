export const ALGORITHM = (<const>[
  {
    sid: 'rsa',
    name: 'rsa',
    modulusLength: 2048,
    publicEncodingType: 'spki',
    publicEncodingFormat: 'der',
    privateEncodingType: 'pkcs8',
    privateEncodingFormat: 'der',
  },
  {
    sid: 'dsa',
    name: 'dsa',
    modulusLength: 2048,
    divisorLength: 256,
    publicEncodingType: 'spki',
    publicEncodingFormat: 'der',
    privateEncodingType: 'pkcs8',
    privateEncodingFormat: 'der',
  },
  {
    sid: 'secp256k1',
    name: 'ec',
    namedCurve: 'secp256k1',
    publicEncodingType: 'spki',
    publicEncodingFormat: 'der',
    privateEncodingType: 'sec1',
    privateEncodingFormat: 'der',
  },
]) satisfies {
  sid: string;
  name: 'rsa' | 'rsa-pss' | 'dsa' | 'ec' | 'ed25519' | 'ed448' | 'x25519' | 'x448';
  namedCurve?: string;
  modulusLength?: number;
  divisorLength?: number;
  publicEncodingType: 'pkcs1' | 'spki' | 'pkcs8' | 'sec1';
  publicEncodingFormat: 'pem' | 'der';
  privateEncodingType: 'sec1' | 'pkcs1' | 'pkcs8';
  privateEncodingFormat: 'pem' | 'der';
  privateEncodingCipher?: string;
  privateEncodingPassphrase?: string;
}[];
