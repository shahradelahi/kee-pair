const crypto = require("crypto");

export const algorithms: Algorithm[] = [
   {
      sid: 'rsa',
      name: 'rsa',
      module_length: 2048,
      public_encoding_type: 'spki',
      public_encoding_format: 'der',
      private_encoding_type: 'pkcs8',
      private_encoding_format: 'der'
   },
   {
      sid: 'dsa',
      name: 'dsa',
      module_length: 2048,
      divisor_length: 256,
      public_encoding_type: 'spki',
      public_encoding_format: 'der',
      private_encoding_type: 'pkcs8',
      private_encoding_format: 'der'
   },
   {
      sid: 'secp256k1',
      name: 'ec',
      named_curve: 'secp256k1',
      public_encoding_type: 'spki',
      public_encoding_format: 'der',
      private_encoding_type: 'sec1',
      private_encoding_format: 'der'
   },
];

export type Algorithm = {
   sid: string
   name: 'rsa' | 'rsa-pss' | 'dsa' | 'ec' | 'ed25519' | 'ed448' | 'x25519' | 'x448'
   named_curve?: string
   module_length?: number
   divisor_length?: number
   public_encoding_type: 'pkcs1' | 'spki' | 'pkcs8' | 'sec1'
   public_encoding_format: 'pem' | 'der'
   private_encoding_type: 'sec1' | 'pkcs1' | 'pkcs8'
   private_encoding_format: 'pem' | 'der'
   private_encoding_cipher?: string
   private_encoding_passphrase?: string
};

export type HashAlgorithmIdentifier = 'sha1' | 'sha256' | 'sha384' | 'sha512' | 'md5' | 'md5-sha1';
export type KeePairAlgorithm = 'rsa' | 'dsa' | 'secp256k1';


export class KeePair {

   readonly publicKey: string;
   readonly privateKey: string;
   readonly algorithm: string;

   constructor(publicKey: string, privateKey: string, algorithm: KeePairAlgorithm) {
      this.publicKey = publicKey;
      this.privateKey = privateKey;
      this.algorithm = algorithm;
   }

   static async generate(algorithm: KeePairAlgorithm): Promise<KeePair> {

      const algorithmData = algorithms.find(a => a.sid === algorithm.toLowerCase());

      if (!algorithmData) {
         throw new Error(`Algorithm "${algorithm}" is not supported.`);
      }

      const {publicKey, privateKey} = crypto.generateKeyPairSync(algorithmData.name as any, {
         modulusLength: algorithmData.module_length,
         ...(algorithmData.named_curve !== null ? {namedCurve: algorithmData.named_curve} : {}),
         ...(algorithmData.divisor_length !== null ? {divisorLength: algorithmData.divisor_length} : {})
      });

      return new KeePair(
          publicKey.export({
             type: algorithmData.public_encoding_type,
             format: (algorithmData.public_encoding_format) as any
          }).toString('hex'),
          privateKey.export({
             type: algorithmData.private_encoding_type,
             format: (algorithmData.private_encoding_format) as any
          }).toString('hex'),
          algorithm
      );
   }

   static async fromPrivateKey(privateKey: string, algorithm: KeePairAlgorithm): Promise<KeePair> {

      const algorithmData = algorithms.find(a => a.sid === algorithm.toLowerCase());

      if (!algorithmData) {
         throw new Error(`Algorithm for private key "${privateKey}" is not supported.`);
      }

      const key = crypto.createPrivateKey({
         key: Buffer.from(privateKey, 'hex'),
         type: algorithmData.private_encoding_type,
         format: (algorithmData.private_encoding_format) as any,
      });

      const publicKey = crypto.createPublicKey(key).export({
         type: algorithmData.public_encoding_type,
         format: (algorithmData.public_encoding_format) as any
      }).toString('hex');

      return new KeePair(publicKey, privateKey, algorithm);
   }

   sign(data: string, algorithm: HashAlgorithmIdentifier): string {

      const algorithmData = algorithms.find(a => a.sid === this.algorithm.toLowerCase());

      if (!algorithmData) {
         throw new Error(`Algorithm "${this.algorithm}" is not supported.`);
      }

      const key = crypto.createPrivateKey({
         key: Buffer.from(this.privateKey, 'hex'),
         type: algorithmData.private_encoding_type,
         format: (algorithmData.private_encoding_format) as any,
      });

      return crypto
          .createSign(algorithm.toLowerCase())
          .update(data)
          .sign(key)
          .toString('hex');
   }

   verify(data: string, signature: string, algorithm: HashAlgorithmIdentifier): boolean {

      const algorithmData = algorithms.find(a => a.sid === this.algorithm.toLowerCase());

      if (!algorithmData) {
         throw new Error(`Algorithm "${this.algorithm}" is not supported.`);
      }

      const key = crypto.createPublicKey({
         key: Buffer.from(this.publicKey, 'hex'),
         type: (algorithmData.public_encoding_type) as any,
         format: (algorithmData.public_encoding_format) as any,
      });

      return crypto
          .createVerify(algorithm.toLowerCase())
          .update(data)
          .verify(key, Buffer.from(signature, 'hex'));
   }

}
