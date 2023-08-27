import { WebSdkEncryptionSupport, envSdk } from "./channel-definitions";
var WebSdkAESVersion = 1;
var WebSdkAESDataType = {
    Binary: 1,
    UnicodeString: 2,
    UTF8String: 3
};
function utf8ToBase64(str) {
    const binstr = utf8ToBinaryString(str);
    return btoa(binstr);
}
function base64ToUtf8(b64) {
    const binstr = atob(b64);
    return binaryStringToUtf8(binstr);
}
function utf8ToBinaryString(str) {
    const escstr = encodeURIComponent(str);
    return escstr.replace(/%([0-9A-F]{2})/g, (_m, p1) => String.fromCharCode(parseInt(p1, 16)));
}
function binaryStringToUtf8(binstr) {
    const escstr = binstr.replace(/(.)/g, function (_m, p1) {
        let code = p1.charCodeAt(0).toString(16).toUpperCase();
        if (code.length < 2) {
            code = '0' + code;
        }
        return `%${code}`;
    });
    return decodeURIComponent(escstr);
}
function xor(key, data) {
    const strArr = Array.prototype.map.call(data, (x) => x);
    return strArr.map((char, idx) => String.fromCharCode(char.charCodeAt(0) ^ keyCharAt(key, idx))).join('');
    function keyCharAt(key, i) {
        return key.charCodeAt(Math.floor(i % key.length));
    }
}
function getHdr(buf) {
    const dv = new DataView(buf);
    return {
        version: dv.getUint8(0),
        type: dv.getUint8(1),
        length: dv.getUint32(2, true),
        offset: dv.getUint16(6, true),
    };
}
function setHdr(buf, type) {
    const dv = new DataView(buf);
    dv.setUint8(0, WebSdkAESVersion); // set version
    dv.setUint8(1, type); // set type
    dv.setUint32(2, buf.byteLength - 8, true); // set length
    dv.setUint16(6, 8, true); // set offset
}
function ab2str(buf) {
    return new Promise(function (resolve, reject) {
        const blob = new Blob([new Uint8Array(buf)]);
        const fileReader = new FileReader();
        fileReader.onload = function (event) {
            return resolve(event.target?.result);
        };
        fileReader.onerror = function (event) {
            return reject(event.target?.error);
        };
        fileReader.readAsText(blob, 'utf-16');
    });
}
function str2ab(str) {
    const buf = new ArrayBuffer(str.length * 2 + 8); // 2 bytes for each char
    setHdr(buf, WebSdkAESDataType.UnicodeString); // unicode string
    const bufView = new Uint16Array(buf, 8);
    for (var i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}
function binary2ab(bin) {
    const buf = new ArrayBuffer(bin.length + 8);
    setHdr(buf, WebSdkAESDataType.Binary); // binary string
    const bufSrc = new Uint8Array(bin);
    const bufDest = new Uint8Array(buf, 8);
    bufDest.set(bufSrc);
    return buf;
}
/////////////////////////////////////////////////////////////////////////////
// AES encryption wrappers
// So far we will use AES-CBC 256bit encryption with 128bit IV vector.
// You can use crypto.generateKey or crypto.importKey,
// but since I'm always either going to share, store, or receive a key
// I don't see the point of using 'generateKey' directly
function generateKey(rawKey) {
    const usages = ['encrypt', 'decrypt'];
    const extractable = false;
    return globalThis.crypto.subtle.importKey('raw', rawKey, { name: 'AES-CBC' }, extractable, usages);
}
function AESEncryption(key, M1, data) {
    const iv = new Uint8Array(hexToArray(M1).buffer, 0, 16);
    let buff;
    if (typeof data === 'string')
        buff = str2ab(data);
    else
        buff = binary2ab(data);
    return encryptAES(buff, key, iv);
    function encryptAES(data, key, iv) {
        return generateKey(key).then(function (key) {
            return encrypt(data, key, iv);
        });
        function encrypt(data, key, iv) {
            return globalThis.crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, key, data); // a public value that should be generated for changes each time
        }
    }
}
function AESDecryption(key, M1, data) {
    const iv = new Uint8Array(hexToArray(M1).buffer, 0, 16);
    return decryptAES(data, key, iv).then(function aa(data) {
        const hdr = getHdr(data);
        if (hdr.version !== WebSdkAESVersion) {
            throw new Error("Invalid data version!");
        }
        switch (hdr.type) {
            case WebSdkAESDataType.Binary: {
                return promisefy(data.slice(hdr.offset));
            }
            case WebSdkAESDataType.UnicodeString: {
                return ab2str(data.slice(hdr.offset));
            }
            default: {
                throw new Error("Invalid data type!");
            }
        }
        //return ab2str(data);
    });
    function decryptAES(data, key, iv) {
        return generateKey(key).then(function (key) {
            return decrypt(data, key, iv);
        });
        function decrypt(data, key, iv) {
            return globalThis.crypto.subtle.decrypt({ name: 'AES-CBC', iv: iv }, key, data); // a public value that should be generated for changes each time
        }
    }
}
/////////////////////////////////////////////////////////////////////////////
export function encode(key, M1, data) {
    if (!key || !M1) {
        throw new Error("Invalid key|M1");
    }
    switch (envSdk.version) {
        case WebSdkEncryptionSupport.AESEncryption: {
            return AESEncryption(key, M1, data);
        }
        case WebSdkEncryptionSupport.Encryption: {
            return promisefy(utf8ToBase64(xor(M1, data)));
        }
        case WebSdkEncryptionSupport.Encoding: {
            return promisefy(utf8ToBase64(data));
        }
        default: {
            return promisefy(data);
        }
    }
}
export function decode(key, M1, data) {
    if (!key || !M1) {
        throw new Error("Invalid key|M1");
    }
    switch (envSdk.version) {
        case WebSdkEncryptionSupport.AESEncryption: {
            return AESDecryption(key, M1, data);
        }
        case WebSdkEncryptionSupport.Encryption: {
            return promisefy(xor(M1, base64ToUtf8(data)));
        }
        case WebSdkEncryptionSupport.Encoding: {
            return promisefy(base64ToUtf8(data));
        }
        default: {
            return promisefy(data);
        }
    }
}
function hexToArray(hex) {
    if (hex.length % 2 === 1) {
        throw new Error("hexToBytes can't have a string with an odd number of characters.");
    }
    if (hex.indexOf("0x") === 0) {
        hex = hex.slice(2);
    }
    return new Uint8Array((hex.match(/../g) || []).map((x) => parseInt(x, 16)));
}
function promisefy(data) {
    return new Promise(function (resolve, reject) {
        setTimeout(function () {
            resolve(data);
        });
    });
}
export function hexToBytes(hex) {
    return hexToArray(hex);
}
