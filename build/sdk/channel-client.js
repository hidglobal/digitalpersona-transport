import { WebChannelOptions, envSdk, traceSdk } from './channel-definitions';
import { WebChannelClientImpl } from './channel-client-implementation';
export class WebChannelClient {
    constructor(dpAgentChannelId, options) {
        if (options) {
            traceSdk(options);
            const o = new WebChannelOptions(options);
            envSdk.debug = o.debug;
            envSdk.version = o.version;
        }
        this.impl = new WebChannelClientImpl(dpAgentChannelId);
    }
    connect() {
        return this.impl.connect();
    }
    ;
    disconnect() {
        return this.impl.disconnect();
    }
    ;
    isConnected() {
        return this.impl.isConnected();
    }
    ;
    sendDataBin(data) {
        this.impl.sendDataBin(data);
    }
    ;
    sendDataTxt(data) {
        this.impl.sendDataTxt(data);
    }
    ;
    resetReconnectTimer() {
        this.impl.stopReconnectTimer();
    }
    ;
    get onConnectionFailed() { return this.impl.onConnectionFailed; }
    set onConnectionFailed(v) { this.impl.onConnectionFailed = v; }
    get onConnectionSucceed() { return this.impl.onConnectionSucceed; }
    set onConnectionSucceed(v) { this.impl.onConnectionSucceed = v; }
    get onDataReceivedBin() { return this.impl.onDataReceivedBin; }
    set onDataReceivedBin(v) { this.impl.onDataReceivedBin = v; }
    get onDataReceivedTxt() { return this.impl.onDataReceivedTxt; }
    set onDataReceivedTxt(v) { this.impl.onDataReceivedTxt = v; }
}
