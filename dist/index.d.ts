export declare const algorithms: Algorithm[];
export declare type Algorithm = {
    sid: string;
    name: 'rsa' | 'rsa-pss' | 'dsa' | 'ec' | 'ed25519' | 'ed448' | 'x25519' | 'x448';
    named_curve?: string;
    module_length?: number;
    divisor_length?: number;
    public_encoding_type: 'pkcs1' | 'spki' | 'pkcs8' | 'sec1';
    public_encoding_format: 'pem' | 'der';
    private_encoding_type: 'sec1' | 'pkcs1' | 'pkcs8';
    private_encoding_format: 'pem' | 'der';
    private_encoding_cipher?: string;
    private_encoding_passphrase?: string;
};
export declare type HashAlgorithmIdentifier = 'sha1' | 'sha256' | 'sha384' | 'sha512' | 'md5' | 'md5-sha1';
export declare type KeePairAlgorithm = 'rsa' | 'dsa' | 'secp256k1';
export declare class KeePair {
    readonly publicKey: string;
    readonly privateKey: string;
    readonly algorithm: string;
    constructor(publicKey: string, privateKey: string, algorithm: KeePairAlgorithm);
    static generate(algorithm: KeePairAlgorithm): Promise<KeePair>;
    static fromPrivateKey(privateKey: string, algorithm: KeePairAlgorithm): Promise<KeePair>;
    sign(data: string, algorithm: HashAlgorithmIdentifier): string;
    verify(data: string, signature: string, algorithm: HashAlgorithmIdentifier): boolean;
}
