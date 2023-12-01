import { envSdk, traceSdk } from './channel-definitions';
import { ErrorOrDataResult, configurator } from './configurator';
import { FixedQueue } from './utils';
import { generateSessionKey } from './session-key';
import * as cipher from './cipher';

export type OnError = null | ((reason?: Event | string) => void);
export type OnConnectionFailed = null | ((reason?: string) => void);
export type OnConnectionSucceed = null | (() => void);
export type OnDataReceivedBin = null | ((data: any) => void);
export type OnDataReceivedTxt = null | ((data: any) => void);

const consts = {
    wsReconnectInterval: 5000,
    wsThreshold: 10240,     // max number of buffered bytes (10k)
    mqInterval: 1000,       // interval to process message queue and send data over web-socket if buffer size is less then the threshold
    mqLimit: 100,           // maximum queue size, when reaching this limit the oldest messages will be removed from the queue.
}

export class WebChannelClientImpl {
    private webSocket: null | WebSocket = null;
    private sessionKey: Uint8Array | null = null;
    private M1: string | undefined;
    private channelId: string; // DpAgent channel Id

    private mq: FixedQueue = new FixedQueue(consts.mqLimit); // message queue
    private mqIntervalId: ReturnType<typeof setInterval> | null = null;
    private reconnectTimer: ReturnType<typeof setInterval> | null = null;

    public onError: OnError = null;
    public onConnectionFailed: OnConnectionFailed = null;
    public onConnectionSucceed: OnConnectionSucceed = null;
    public onDataReceivedBin: OnDataReceivedBin = null;
    public onDataReceivedTxt: OnDataReceivedTxt = null;

    constructor(dpAgentChannelId: string) {
        traceSdk(`wci.constructor({version: ${envSdk.version}, dpAgentClientId: "${dpAgentChannelId}"})`); // wci - wc implementation
        if (!dpAgentChannelId) {
            throw new Error("clientPath cannot be empty");
        }
        this.channelId = dpAgentChannelId;
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

            this.webSocket.onmessage = (event: MessageEvent<any>) => this._onMessage(event);

            this.webSocket.onopen = () => {
                traceSdk("wci.wsonopen()");
                this.webSocket && (this.webSocket.onerror = this.onRuntimeError);
                resolve();
            };

            this.webSocket.onclose = () => {
                traceSdk("wci.wsonclose()");
                this.removeEventHandlers(true);
            };

            this.webSocket.onerror = (...args) => {
                traceSdk('wci.wsonerror()', args);
                reject(new Error("WebSocket connection failed"));
            };
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

        this.stopMqInterval();
        isFailed && this.onConnectionFailed?.();
    }

    private _onMessage(event: MessageEvent<any>): void {
        cipher.decode(this.sessionKey, this.M1, event.data)
            .then((data) => (
                typeof data === 'string'
                    ? this.onDataReceivedTxt?.(data)
                    : this.onDataReceivedBin?.(data)
            ));
    }

    public sendDataBin(data: number[]): void {
        cipher.encode(this.sessionKey, this.M1, data)
            .then((data) => this.sendData(data)).catch((error) => this.reportError(error));
    }

    public sendDataTxt(data: string): void {
        cipher.encode(this.sessionKey, this.M1, data)
            .then((data) => this.sendData(data)).catch((error) => this.reportError(error));;
    }

    public sendData(data: any): void { // Sends message if channel is ready otherwise, adds message to the queue.
        if (!this.wssend(data)) {
            this.mq.push(data);
        }
    }

    private wssend(data: any): boolean { // Sends data over web socket
        if (!this.isConnected() || !this.webSocket) {
            this.reportError("WebSocket is not connected");
            return false;
        }

        if (this.webSocket.bufferedAmount >= consts.wsThreshold) {
            this.startMqInterval();
            return false;
        }

        this.webSocket.send(data);
        return true;
    }

    /**
     * Process message queue (Mq) will send messages from queue.
     */
    private processMq(): void {
        if (this.mq.length) {
            traceSdk(`wci.processMessageQueue(${this.mq.length})`);

            while (this.mq.length > 0) {
                if (!this.wssend(this.mq.items[0])) {
                    break;
                }
                this.mq.splice(0, 1);
            }

            if (!this.mq.length) {
                this.stopMqInterval();
            }
        }
    }

    private stopMqInterval(): void {
        if (this.mqIntervalId) {
            clearInterval(this.mqIntervalId);
            this.mqIntervalId = null;
        }
    }

    private startMqInterval(): void {
        if (!this.mqIntervalId) {
            this.mqIntervalId = setInterval(() => this.processMq(), consts.mqInterval);
        }
    }

    private reportError = (error: unknown) => {
        const msg = (error instanceof Error ? error.message : (error as any).toString()) || 'tm.error';
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
            const connectionUrl = await configurator.getDpAgentConnectionUrl({ dpAgentChannelId: this.channelId, M1: this.M1 });

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
            this.processMq();
        } catch (error) {
            this.onConnectionFailed?.((error instanceof Error ? error.message : (error as any).toString()) || 'tm.error.connect');
        }
    }

    /**
    * Returns true if web socket is ready to transfer data.
    */
    public isConnected(): boolean {
        return this.webSocket?.readyState === WebSocket.OPEN;
    }

    public stopReconnectTimer(): void {
        this.reconnectTimer && (clearInterval(this.reconnectTimer), this.reconnectTimer = null);
    }

    public startReconnectTimer(nTimes: number = 1): void {
        this.stopReconnectTimer();
        this.reconnectTimer = setInterval(() => this.tryConnectNTimes(nTimes), consts.wsReconnectInterval);
    }

    public async connect(nTimes: number = 3): Promise<void> {
        await this.tryConnectNTimes(nTimes);
    }

    public async disconnect(): Promise<void> {
        await this.wsdisconnect();
    }

} //class WebChannelClientImpl
