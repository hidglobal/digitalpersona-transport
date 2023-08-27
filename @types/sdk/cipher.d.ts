export declare function encode(key: Uint8Array | null, M1: string | undefined, data: number[] | string): Promise<ArrayBuffer | string>;
export declare function decode(key: Uint8Array | null, M1: string | undefined, data: ArrayBuffer | string): Promise<ArrayBuffer | string>;
export declare function hexToBytes(hex: string): Uint8Array;
