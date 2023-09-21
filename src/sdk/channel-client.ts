import { OptionsParams, WebChannelOptions, envSdk, traceSdk } from './channel-definitions';
import { OnConnectionFailed, OnConnectionSucceed, OnDataReceivedBin, OnDataReceivedTxt, WebChannelClientImpl } from './channel-client-implementation';

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

    get onConnectionFailed(): OnConnectionFailed { return this.impl.onConnectionFailed; }
    set onConnectionFailed(cb: OnConnectionFailed) { this.impl.onConnectionFailed = cb; }

    get onConnectionSucceed(): OnConnectionSucceed { return this.impl.onConnectionSucceed; }
    set onConnectionSucceed(cb: OnConnectionSucceed) { this.impl.onConnectionSucceed = cb; }

    get onDataReceivedBin(): OnDataReceivedBin { return this.impl.onDataReceivedBin; }
    set onDataReceivedBin(cb: OnDataReceivedBin) { this.impl.onDataReceivedBin = cb; }

    get onDataReceivedTxt(): OnDataReceivedTxt { return this.impl.onDataReceivedTxt; }
    set onDataReceivedTxt(cb: OnDataReceivedTxt) { this.impl.onDataReceivedTxt = cb; }
}
