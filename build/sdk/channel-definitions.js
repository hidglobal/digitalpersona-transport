export const WebSdkEncryptionSupport = {
    None: 1,
    Encoding: 2,
    Encryption: 3,
    AESEncryption: 4,
};
export const WebSdkDataSupport = {
    Binary: 1,
    String: 2,
};
export function traceSdk(...args) {
    if (envSdk.debug) {
        console.log(...args);
    }
}
export class WebChannelOptions {
    constructor(options = {}) {
        this._version = WebSdkEncryptionSupport.AESEncryption;
        this.debug = options.debug || false;
        if (!!options.version) {
            this.version = options.version;
        }
    }
    get version() {
        return this._version;
    }
    set version(v) {
        if (!v || !Object.values(WebSdkEncryptionSupport).includes(v)) {
            throw new Error("invalid WebSdkEncryptionSupport");
        }
        if (envSdk.version >= WebSdkEncryptionSupport.AESEncryption && !isCryptoSupported()) {
            envSdk.version = WebSdkEncryptionSupport.Encryption; // if AES encryption is not supported by Browser, set data encryption to old one.
        }
        this._version = v;
    }
}
export function isCryptoSupported() {
    return (typeof globalThis.crypto !== 'undefined') && globalThis.crypto.subtle;
}
export const envSdk = {
    debug: false,
    version: 4,
};
