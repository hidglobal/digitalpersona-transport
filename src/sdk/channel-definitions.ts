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

export function traceSdk(...args: any[]) {
    if (envSdk.debug) {
        console.log(...args);
    }
}

export type OptionsParams = {
    debug?: boolean;
    version?: number;
};

export class WebChannelOptions {
    private _version: number = WebSdkEncryptionSupport.AESEncryption;
    public debug: boolean;

    constructor(options: OptionsParams = {}) {
        this.debug = options.debug || false;

        if (!!options.version) {
            this.version = options.version;
        }
    }

    public get version(): number {
        return this._version;
    }

    public set version(v: number) {
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
    debug: false,       // if true browser console will be used to output debug messages
    version: 4,
};
