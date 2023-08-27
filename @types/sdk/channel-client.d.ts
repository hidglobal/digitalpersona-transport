import { OptionsParams } from './channel-definitions';
export declare class WebChannelClient {
    private impl;
    constructor(dpAgentChannelId: string, options: OptionsParams);
    connect(): Promise<void>;
    disconnect(): Promise<void>;
    isConnected(): boolean;
    sendDataBin(data: number[]): void;
    sendDataTxt(data: any): void;
    resetReconnectTimer(): void;
    get onConnectionFailed(): ((reason?: string | undefined) => void) | null;
    set onConnectionFailed(v: ((reason?: string | undefined) => void) | null);
    get onConnectionSucceed(): (() => void) | null;
    set onConnectionSucceed(v: (() => void) | null);
    get onDataReceivedBin(): ((data: any) => void) | null;
    set onDataReceivedBin(v: ((data: any) => void) | null);
    get onDataReceivedTxt(): ((data: any) => void) | null;
    set onDataReceivedTxt(v: ((data: any) => void) | null);
}
