import { envSdk, WebSdkEncryptionSupport, traceSdk } from './channel-definitions';
import { BigInteger, SRPClient, sjcl } from 'ts-srpclient';
import { ErrorOrDataResult, configurator } from './configurator';
import { FixedQueue, ajax, createDeferredPromise } from './utils';
import * as cipher from './cipher';

export type OnConnectionFailed = WebChannelClientImpl['onConnectionFailed'];
export type OnConnectionSucceed = WebChannelClientImpl['onConnectionSucceed'];
export type OnDataReceivedBin = WebChannelClientImpl['onDataReceivedBin'];
export type OnDataReceivedTxt = WebChannelClientImpl['onDataReceivedTxt'];

export class WebChannelClientImpl {
    private dpAgentChannelId: string;

    private wsThreshold: number = 10240;        // max number of buffered bytes (10k)
    private wsQueueInterval: number = 1000;     // interval to process message queue and send data over web-socket if buffer size is less then the threshold
    private wsQueueLimit: number = 100;         // maximum queue size, when reaching this limit the oldest messages will be removed from the queue.
    private wsReconnectInterval: number = 5000;

    private queue: FixedQueue = new FixedQueue(this.wsQueueLimit);
    private queueInterval: ReturnType<typeof setInterval> | null = null;
    private reconnectTimer: ReturnType<typeof setInterval> | null = null;

    private webSocket: null | WebSocket = null;
    private sessionKey: Uint8Array | null = null;
    private M1: string | undefined;

    public onConnectionFailed: null | ((reason?: string) => void) = null;
    public onConnectionSucceed: null | (() => void) = null;
    public onDataReceivedBin: null | ((data: any) => void) = null;
    public onDataReceivedTxt: null | ((data: any) => void) = null;

    constructor(dpAgentChannelId: string) {
        traceSdk(`wccImpl.constructor({version: ${envSdk.version}, dpAgentClientId: "${dpAgentChannelId}"})`);
        if (!dpAgentChannelId) {
            throw new Error("clientPath cannot be empty");
        }
        this.dpAgentChannelId = dpAgentChannelId;
    }

    /**
    * Connects to web socket server and setups all event listeners
    */
    private wsconnect(url: string): Promise<void> {
        traceSdk(`wccImpl.wsconnect(${url})`);

        const deferredPromise = createDeferredPromise();

        if (this.webSocket && this.webSocket.readyState !== WebSocket.CLOSED) {
            throw new Error("disconnect has not been called");
        }

        this.webSocket = new WebSocket(url);
        this.webSocket.binaryType = 'arraybuffer'; // we need binary type 'arraybuffer' because default type 'blob' is not working

        this.webSocket.onclose = (event) => {
            traceSdk("wccImpl.wsonclose()");
            return this.wsonclose(true);
        };

        this.webSocket.onopen = function (event) {
            traceSdk("wccImpl.wsonopen()");
            deferredPromise.resolve();
        };

        this.webSocket.onerror = function (event) {
            traceSdk(`wccImpl.wsonerror(${arguments})`);
            return deferredPromise.reject(new Error("WebSocket connection failed."));
        };

        this.webSocket.onmessage = (event: MessageEvent<any>) => this.wsonmessage(event);

        return deferredPromise.promise;
    }

    /**
    * Closes web socket connection and cleans up all event listeners
    */
    private wsdisconnect(): Promise<void> {
        const self = this;
        const deferredPromise = createDeferredPromise();

        if (!this.webSocket || this.webSocket.readyState !== WebSocket.OPEN) {
            deferredPromise.resolve();
        } else {
            this.webSocket.onclose = function (event) {
                self.wsonclose(false);
                deferredPromise.resolve();
            };
            this.webSocket.close();
        }

        return deferredPromise.promise;
    }

    wsonclose(isFailed: boolean) {
        traceSdk("wccImpl.wsonclose()");

        if (this.webSocket) {
            this.webSocket.onclose = null;
            this.webSocket.onopen = null;
            this.webSocket.onmessage = null;
            this.webSocket.onerror = null;
        }

        this.stopMessageQueueInterval();
        isFailed && this.onConnectionFailed?.();
    }

    private wsonmessage(event: MessageEvent<any>) {
        cipher.decode(this.sessionKey, this.M1, event.data)
            .then((data) => typeof data === 'string' ? this.onDataReceivedTxt?.(data) : this.onDataReceivedBin?.(data));
    }

    public sendDataBin(data: number[]): void {
        cipher.encode(this.sessionKey, this.M1, data).then((data) => this.sendData(data)).catch(this.reportError);
    }

    public sendDataTxt(data: string): void {
        cipher.encode(this.sessionKey, this.M1, data).then((data) => this.sendData(data)).catch(this.reportError);;
    }

    public sendData(data: any): void { // Sends message if channel is ready otherwise, adds message to the queue.
        if (!this.wssend(data)) {
            this.queue.push(data);
        }
    }

    public wssend(data: any): boolean { // Sends data over web socket
        if (!this.isConnected() || !this.webSocket) {
            return false;
        }

        if (this.webSocket.bufferedAmount >= this.wsThreshold) {
            this.startMessageQueueInterval();
            return false;
        }

        this.webSocket.send(data);
        return true;
    }

    /**
    * True if web socket is ready for transferring data
    */
    public isConnected(): boolean {
        return !!this.webSocket && this.webSocket.readyState === WebSocket.OPEN;
    }

    private stopMessageQueueInterval(): void {
        this.queueInterval && (clearInterval(this.queueInterval), this.queueInterval = null);
    }

    private startMessageQueueInterval(): void {
        if (!this.queueInterval) {
            this.queueInterval = setInterval(() => this.processMessageQueue(), this.wsQueueInterval);
        }
    }

    /**
    * Sends messages from a queue if any. Initiates secure connection if needed and has not been yet initiated.
    */
    private processMessageQueue(): void {
        if (!this.queue.length) {
            return;
        }
        traceSdk(`wccImpl.processMessageQueue(${this.queue.length})`);

        for (var i = 0; i < this.queue.length;) {
            if (!this.wssend(this.queue.items[i])) {
                break;
            }
            this.queue.splice(i, 1);
        }
        if (this.queue.length === 0) {
            this.stopMessageQueueInterval();
        }
    }

    public stopReconnectTimer(): void {
        this.reconnectTimer && (clearInterval(this.reconnectTimer), this.reconnectTimer = null);
    }

    public startReconnectTimer(): void {
        this.stopReconnectTimer();
        this.reconnectTimer = setInterval(() => this.tryConnectNTimes(1), this.wsReconnectInterval);
    }

    public async connect(): Promise<void> {
        await this.tryConnectNTimes(3);
    }

    public async disconnect(): Promise<void> {
        await this.wsdisconnect();
    }

    private reportError = (error: unknown) => {
        const msg = (error instanceof Error ? error.message : (error as any).toString()) || 'tm.error.connect';
        console.error(msg);
    };

    private async generateSessionKey(): Promise<ErrorOrDataResult> {
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
            this.sessionKey = cipher.hexToBytes(sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(sjcl.codec.hex.toBits(K))));
            this.M1 = M1;

            return { data: M1 };
        } catch (error) {
            return { error: (error instanceof Error ? error.message : (error as any).toString()) || 'tm.error.key' };
        }
    }

    /**
    * Sets up connection with parameters from configurator (generates session key and connects to websocket server).
    */
    private async setupSecureChannel(): Promise<ErrorOrDataResult> {
        traceSdk('wccImpl.setupSecureChannel()');

        const res = await this.generateSessionKey();
        if (res.error) {
            return res;
        }

        try {
            const connectionUrl = await configurator.getDpAgentConnectionUrl({ dpAgentChannelId: this.dpAgentChannelId, M1: this.M1 });
            await this.wsconnect(connectionUrl);
            return {};
        } catch (error) {
            traceSdk(error);
            return { error: (error instanceof Error ? error.message : (error as any).toString()) || 'tm.error.key' };
        }
    }

    private async tryConnectNTimes(nAttempts: number): Promise<void> {
        traceSdk('wccImpl.connectInternal()');

        this.stopReconnectTimer();
        if (this.isConnected()) {
            return;
        }

        try {
            await configurator.ensureLoaded();

            let attemptsLeft = nAttempts;
            let res2: ErrorOrDataResult;
            do {
                res2 = await this.setupSecureChannel();
            } while (!!res2.error && --attemptsLeft > 0);

            if (res2.error) {
                throw new Error(res2.error);
            }

            this.onConnectionSucceed?.();
            this.processMessageQueue();
        } catch (error) {
            this.onConnectionFailed?.((error instanceof Error ? error.message : (error as any).toString()) || 'tm.error.connect');
        }
    }

} //class WebChannelClientImpl
