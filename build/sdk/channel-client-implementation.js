import { envSdk, WebSdkEncryptionSupport, traceSdk } from './channel-definitions';
import { BigInteger, SRPClient, sjcl } from 'ts-srpclient';
import { configurator } from './configurator';
import { FixedQueue, ajax, createDeferredPromise } from './utils';
import * as cipher from './cipher';
export class WebChannelClientImpl {
    constructor(dpAgentChannelId) {
        this.wsThreshold = 10240; // max number of buffered bytes (10k)
        this.wsQueueInterval = 1000; // interval to process message queue and send data over web-socket if buffer size is less then the threshold
        this.wsQueueLimit = 100; // maximum queue size, when reaching this limit the oldest messages will be removed from the queue.
        this.wsReconnectInterval = 5000;
        this.queue = new FixedQueue(this.wsQueueLimit);
        this.queueInterval = null;
        this.reconnectTimer = null;
        this.webSocket = null;
        this.sessionKey = null;
        this.onConnectionFailed = null;
        this.onConnectionSucceed = null;
        this.onDataReceivedBin = null;
        this.onDataReceivedTxt = null;
        this.reportError = (error) => {
            const msg = (error instanceof Error ? error.message : error.toString()) || 'tm.error.connect';
            console.error(msg);
        };
        traceSdk(`wccImpl.constructor({version: ${envSdk.version}, dpAgentClientId: "${dpAgentChannelId}"})`);
        if (!dpAgentChannelId) {
            throw new Error("clientPath cannot be empty");
        }
        this.dpAgentChannelId = dpAgentChannelId;
    }
    /**
    * Connects to web socket server and setups all event listeners
    */
    wsconnect(url) {
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
        this.webSocket.onmessage = (event) => this.wsonmessage(event);
        return deferredPromise.promise;
    }
    /**
    * Closes web socket connection and cleans up all event listeners
    */
    wsdisconnect() {
        const self = this;
        const deferredPromise = createDeferredPromise();
        if (!this.webSocket || this.webSocket.readyState !== WebSocket.OPEN) {
            deferredPromise.resolve();
        }
        else {
            this.webSocket.onclose = function (event) {
                self.wsonclose(false);
                deferredPromise.resolve();
            };
            this.webSocket.close();
        }
        return deferredPromise.promise;
    }
    wsonclose(isFailed) {
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
    wsonmessage(event) {
        cipher.decode(this.sessionKey, this.M1, event.data)
            .then((data) => typeof data === 'string' ? this.onDataReceivedTxt?.(data) : this.onDataReceivedBin?.(data));
    }
    sendDataBin(data) {
        cipher.encode(this.sessionKey, this.M1, data).then((data) => this.sendData(data)).catch(this.reportError);
    }
    sendDataTxt(data) {
        cipher.encode(this.sessionKey, this.M1, data).then((data) => this.sendData(data)).catch(this.reportError);
        ;
    }
    sendData(data) {
        if (!this.wssend(data)) {
            this.queue.push(data);
        }
    }
    wssend(data) {
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
    isConnected() {
        return !!this.webSocket && this.webSocket.readyState === WebSocket.OPEN;
    }
    stopMessageQueueInterval() {
        this.queueInterval && (clearInterval(this.queueInterval), this.queueInterval = null);
    }
    startMessageQueueInterval() {
        if (!this.queueInterval) {
            this.queueInterval = setInterval(() => this.processMessageQueue(), this.wsQueueInterval);
        }
    }
    /**
    * Sends messages from a queue if any. Initiates secure connection if needed and has not been yet initiated.
    */
    processMessageQueue() {
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
    stopReconnectTimer() {
        this.reconnectTimer && (clearInterval(this.reconnectTimer), this.reconnectTimer = null);
    }
    startReconnectTimer() {
        this.stopReconnectTimer();
        this.reconnectTimer = setInterval(() => this.tryConnectNTimes(1), this.wsReconnectInterval);
    }
    async connect() {
        await this.tryConnectNTimes(3);
    }
    async disconnect() {
        await this.wsdisconnect();
    }
    async generateSessionKey() {
        try {
            const srpData = configurator.session.srpClient;
            if (!srpData?.p1 || !srpData.p2 || !srpData.salt) {
                return { error: "No data available for authentication" };
            }
            const srpClient = new SRPClient(srpData.p1, srpData.p2);
            let a;
            do {
                a = srpClient.srpRandom();
            } while (!srpClient.canCalculateA(a));
            const A = srpClient.calculateA(a);
            const response = await ajax('post', configurator.getDpHostConnectionUrl(), {
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
        }
        catch (error) {
            return { error: (error instanceof Error ? error.message : error.toString()) || 'tm.error.key' };
        }
    }
    /**
    * Sets up connection with parameters from configurator (generates session key and connects to websocket server).
    */
    async setupSecureChannel() {
        traceSdk('wccImpl.setupSecureChannel()');
        const res = await this.generateSessionKey();
        if (res.error) {
            return res;
        }
        try {
            const connectionUrl = configurator.getDpAgentConnectionUrl({ dpAgentChannelId: this.dpAgentChannelId, M1: this.M1 });
            await this.wsconnect(connectionUrl);
            return {};
        }
        catch (error) {
            traceSdk(error);
            return { error: (error instanceof Error ? error.message : error.toString()) || 'tm.error.key' };
        }
    }
    async tryConnectNTimes(nAttempts) {
        traceSdk('wccImpl.connectInternal()');
        this.stopReconnectTimer();
        if (this.isConnected()) {
            return;
        }
        try {
            const res = await configurator.ensureLoaded();
            if (res.error) {
                throw new Error(res.error);
            }
            let attemptsLeft = nAttempts;
            let res2;
            do {
                res2 = await this.setupSecureChannel();
            } while (!!res2.error && --attemptsLeft > 0);
            if (res2.error) {
                throw new Error(res2.error);
            }
            this.onConnectionSucceed?.();
            this.processMessageQueue();
        }
        catch (error) {
            this.onConnectionFailed?.((error instanceof Error ? error.message : error.toString()) || 'tm.error.connect');
        }
    }
} //class WebChannelClientImpl
