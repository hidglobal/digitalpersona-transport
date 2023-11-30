import { envSdk, traceSdk } from './channel-definitions';
import { ErrorOrDataResult, configurator } from './configurator';
import { FixedQueue } from './utils';
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
        traceSdk(`wci.constructor({version: ${envSdk.version}, dpAgentClientId: "${dpAgentChannelId}"})`); // wci - wc implementation
        if (!dpAgentChannelId) {
            throw new Error("clientPath cannot be empty");
        }
        this.dpAgentChannelId = dpAgentChannelId;
    }

    /**
    * Connects to web socket server and setups all event listeners
    */
    private async wsconnect(url: string): Promise<void> {
        traceSdk(`wci.wsconnect(${url})`);

        if (this.webSocket) {
            if (this.webSocket.readyState !== WebSocket.CLOSED) {
                throw new Error("disconnect has not been called");
            }
            this.removeEventHandlers(false);
        }

        return new Promise<void>((resolve, reject) => {
            this.webSocket = new WebSocket(url);
            this.webSocket.binaryType = 'arraybuffer'; // We need binary type 'arraybuffer' because default type 'blob' is not working

            this.webSocket.onclose = () => {
                traceSdk("wci.wsonclose()");
                this.removeEventHandlers(true);
            };

            this.webSocket.onopen = () => {
                traceSdk("wci.wsonopen()");
                this.webSocket && (this.webSocket.onerror = this.onRuntimeError);
                resolve();
            };

            this.webSocket.onerror = (...args) => {
                traceSdk('wci.wsonerror()', args);
                reject(new Error("WebSocket connection failed."));
            };

            this.webSocket.onmessage = (event: MessageEvent<any>) => this._onMessage(event);
        });
    }

    /**
    * Closes web socket connection and cleans up all event listeners
    */
    private async wsdisconnect(): Promise<void> {
        traceSdk(`wci.wsdisconnect()`);

        return new Promise<void>((resolve, reject) => {
            if (!this.webSocket || this.webSocket.readyState !== WebSocket.OPEN) {
                resolve();
            } else {
                this.webSocket.onclose = () => {
                    this.removeEventHandlers(false);
                    resolve();
                };
                this.webSocket.close();
            }
        });
    }

    private removeEventHandlers(isFailed: boolean): void {
        traceSdk("wci.wsonclose()");

        if (this.webSocket) {
            this.webSocket.onclose = null;
            this.webSocket.onopen = null;
            this.webSocket.onmessage = null;
            this.webSocket.onerror = null;

            this.webSocket = null;
        }

        this.stopMessageQueueInterval();
        isFailed && this.onConnectionFailed?.();
    }

    private _onMessage(event: MessageEvent<any>): void {
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

    private wssend(data: any): boolean { // Sends data over web socket
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

    private stopMessageQueueInterval(): void {
        if (this.queueInterval) {
            clearInterval(this.queueInterval);
            this.queueInterval = null;
        }
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
        traceSdk(`wci.processMessageQueue(${this.queue.length})`);

        while (this.queue.length > 0) {
            if (!this.wssend(this.queue.items[0])) {
                break;
            }
            this.queue.splice(0, 1);
        }

        if (this.queue.length === 0) {
            this.stopMessageQueueInterval();
        }
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
        traceSdk('wci.setupSecureChannel()');

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
        traceSdk('wci.connectInternal()');

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

    /**
    * True if web socket is ready for transferring data
    */
    public isConnected(): boolean {
        return this.webSocket?.readyState === WebSocket.OPEN;
    }

    public stopReconnectTimer(): void {
        this.reconnectTimer && (clearInterval(this.reconnectTimer), this.reconnectTimer = null);
    }

    public startReconnectTimer(nTimes: number = 1): void {
        this.stopReconnectTimer();
        this.reconnectTimer = setInterval(() => this.tryConnectNTimes(nTimes), this.wsReconnectInterval);
    }

    public async connect(nTimes: number = 3): Promise<void> {
        await this.tryConnectNTimes(nTimes);
    }

    public async disconnect(): Promise<void> {
        await this.wsdisconnect();
    }

} //class WebChannelClientImpl
