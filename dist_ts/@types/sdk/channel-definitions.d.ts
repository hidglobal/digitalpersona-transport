export declare const WebSdkEncryptionSupport: {
    None: number;
    Encoding: number;
    Encryption: number;
    AESEncryption: number;
};
export declare const WebSdkDataSupport: {
    Binary: number;
    String: number;
};
export declare function traceSdk(...args: any[]): void;
export type OptionsParams = {
    debug?: boolean;
    version?: number;
};
export declare class WebChannelOptions {
    private _version;
    debug: boolean;
    constructor(options?: OptionsParams);
    get version(): number;
    set version(v: number);
}
export declare function isCryptoSupported(): false | SubtleCrypto;
export declare const envSdk: {
    debug: boolean;
    version: number;
};
