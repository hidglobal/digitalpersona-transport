import { OptionsParams, WebChannelOptions, envSdk, traceSdk } from './channel-definitions';
import { WebChannelClientImpl } from './channel-client-implementation';

export class WebChannelClient {
    private impl: WebChannelClientImpl;

    constructor(dpAgentChannelId: string, options: OptionsParams) {
        if (options) {
            traceSdk(options);

            const o = new WebChannelOptions(options);
            envSdk.debug = o.debug;
            envSdk.version = o.version;
        }

        this.impl = new WebChannelClientImpl(dpAgentChannelId);
    }

    connect(): Promise<void> {
        return this.impl.connect();
    };

    disconnect(): Promise<void> {
        return this.impl.disconnect();
    };

    isConnected(): boolean {
        return this.impl.isConnected();
    };

    sendDataBin(data: number[]): void {
        this.impl.sendDataBin(data);
    };

    sendDataTxt(data: any): void {
        this.impl.sendDataTxt(data);
    };

    resetReconnectTimer() {
        this.impl.stopReconnectTimer();
    };

    get onConnectionFailed() { return this.impl.onConnectionFailed; }
    set onConnectionFailed(v) { this.impl.onConnectionFailed = v; }

    get onConnectionSucceed() { return this.impl.onConnectionSucceed; }
    set onConnectionSucceed(v) { this.impl.onConnectionSucceed = v; }

    get onDataReceivedBin() { return this.impl.onDataReceivedBin; }
    set onDataReceivedBin(v) { this.impl.onDataReceivedBin = v; }

    get onDataReceivedTxt() { return this.impl.onDataReceivedTxt; }
    set onDataReceivedTxt(v) { this.impl.onDataReceivedTxt = v; }
}
