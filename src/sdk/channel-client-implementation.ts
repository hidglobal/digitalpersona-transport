import { envSdk, traceSdk } from './channel-definitions';
import { ErrorOrDataResult, configurator } from './configurator';
import { FixedQueue, createDeferredPromise } from './utils';
import { generateSessionKey } from './session-key';
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

    public onError: null | ((reason?: Event | string) => void) = null;
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

        this.webSocket.onclose = () => {
            traceSdk("wccImpl.wsonclose()");
            this.wsonclose(true);
        };

        this.webSocket.onopen = () => {
            traceSdk("wccImpl.wsonopen()");
            this.webSocket && (this.webSocket.onerror = this.onRuntimeError);
            deferredPromise.resolve();
        };

        this.webSocket.onerror = (...args) => {
            traceSdk(`wccImpl.wsonerror(${args})`);
            deferredPromise.reject(new Error("WebSocket connection failed."));
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

        //TODO: this.webSocket = null;
        //TODO: replace deferredPromise with the real Promise
        //TODO: move generateSessionKey() out of this file - done

        return deferredPromise.promise;
    }

    wsonclose(isFailed: boolean): void {
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

    private wsonmessage(event: MessageEvent<any>): void {
        cipher.decode(this.sessionKey, this.M1, event.data)
            .then((data) => typeof data === 'string' ? this.onDataReceivedTxt?.(data) : this.onDataReceivedBin?.(data));
    }

    public sendDataBin(data: number[]): void {
        cipher.encode(this.sessionKey, this.M1, data)
            .then((data) => this.sendData(data)).catch(this.reportError);
    }

    public sendDataTxt(data: string): void {
        cipher.encode(this.sessionKey, this.M1, data)
            .then((data) => this.sendData(data)).catch(this.reportError);;
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

    private onRuntimeError = (event?: Event | string) => {
        this.onError ? this.onError(event) : this.reportError(event);
    };

    /**
    * Sets up connection with parameters from configurator (generates session key and connects to websocket server).
    */
    private async setupSecureChannel(): Promise<ErrorOrDataResult> {
        traceSdk('wccImpl.setupSecureChannel()');

        const { sessionKey, M1, error } = await generateSessionKey();
        if (error) {
            return { error };
        }

        this.sessionKey = sessionKey || null;
        this.M1 = M1;

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
            let ok: ErrorOrDataResult;
            do {
                ok = await this.setupSecureChannel();
            } while (!!ok.error && --attemptsLeft > 0);

            if (ok.error) {
                throw new Error(ok.error);
            }

            this.onConnectionSucceed?.();
            this.processMessageQueue();
        } catch (error) {
            this.onConnectionFailed?.((error instanceof Error ? error.message : (error as any).toString()) || 'tm.error.connect');
        }
    }

} //class WebChannelClientImpl
