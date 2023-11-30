import { envSdk, WebSdkEncryptionSupport } from './channel-definitions';
import { BigInteger, SRPClient, sjcl } from 'ts-srpclient';
import { configurator } from './configurator';
import { ajax } from './utils';
import * as cipher from './cipher';

export async function generateSessionKey(): Promise<{ sessionKey: Uint8Array; M1: string; error?: undefined; } | { error: string; sessionKey?: undefined; M1?: undefined; }> {
    try {
        const srpData = (await configurator.getSessionStorageData())?.srpClient;
        if (!srpData?.p1 || !srpData.p2 || !srpData.salt) {
            return { error: "No data available for authentication" };
        }

        const srpClient = new SRPClient(srpData.p1, srpData.p2);

        let a: BigInteger;
        do {
            a = srpClient.srpRandom();
        } while (!srpClient.canCalculateA(a));

        const A: BigInteger = srpClient.calculateA(a);

        const response = await ajax<{ version: number; B: BigInteger; }>('post', await configurator.getDpHostConnectionUrl(), {
            username: srpData.p1,
            A: srpClient.toHexString(A),
            version: envSdk.version.toString(),
        });

        envSdk.version = response.version ?? /*old client*/ Math.min(envSdk.version, WebSdkEncryptionSupport.Encryption);

        const B = new BigInteger(response.B, 16);
        const u = srpClient.calculateU(A, B);
        const S = srpClient.calculateS(B, srpData.salt, u, a);
        const K = srpClient.calculateK(S);
        const M1 = srpClient.calculateM(A, B, K, srpData.salt);

        // we will use SHA256 from K as AES 256bit session key
        const sessionKey = cipher.hexToBytes(sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(sjcl.codec.hex.toBits(K))));

        return { sessionKey, M1 };
    } catch (error) {
        return { error: (error instanceof Error ? error.message : (error as any).toString()) || 'tm.error.key' };
    }
}
