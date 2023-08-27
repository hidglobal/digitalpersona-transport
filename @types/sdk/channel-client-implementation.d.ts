export declare class WebChannelClientImpl {
    private dpAgentChannelId;
    private wsThreshold;
    private wsQueueInterval;
    private wsQueueLimit;
    private wsReconnectInterval;
    private queue;
    private queueInterval;
    private reconnectTimer;
    private webSocket;
    private sessionKey;
    private M1;
    onConnectionFailed: null | ((reason?: string) => void);
    onConnectionSucceed: null | (() => void);
    onDataReceivedBin: null | ((data: any) => void);
    onDataReceivedTxt: null | ((data: any) => void);
    constructor(dpAgentChannelId: string);
    /**
    * Connects to web socket server and setups all event listeners
    */
    private wsconnect;
    /**
    * Closes web socket connection and cleans up all event listeners
    */
    private wsdisconnect;
    wsonclose(isFailed: boolean): void;
    private wsonmessage;
    sendDataBin(data: number[]): void;
    sendDataTxt(data: string): void;
    sendData(data: any): void;
    wssend(data: any): boolean;
    /**
    * True if web socket is ready for transferring data
    */
    isConnected(): boolean;
    private stopMessageQueueInterval;
    private startMessageQueueInterval;
    /**
    * Sends messages from a queue if any. Initiates secure connection if needed and has not been yet initiated.
    */
    private processMessageQueue;
    stopReconnectTimer(): void;
    startReconnectTimer(): void;
    connect(): Promise<void>;
    disconnect(): Promise<void>;
    private reportError;
    private generateSessionKey;
    /**
    * Sets up connection with parameters from configurator (generates session key and connects to websocket server).
    */
    private setupSecureChannel;
    private tryConnectNTimes;
}
