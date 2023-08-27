type SRPClientCreds = {
    p1: string;
    p2: string;
    salt: string;
};
type SRPSessionData = {
    port: number;
    host: string;
    secure: boolean;
    srpClient: SRPClientCreds | null;
};
export type ErrorOrDataResult<T = string> = {
    error?: string;
    data?: T;
};
declare class Configurator {
    session: SRPSessionData;
    constructor();
    ensureLoaded(): Promise<ErrorOrDataResult>;
    private parseHostReply;
    getDpHostConnectionUrl(): string;
    getDpAgentConnectionUrl({ dpAgentChannelId, M1 }: {
        dpAgentChannelId: string;
        M1: string | undefined;
    }): string;
    get sessionId(): string | null;
    set sessionId(value: string | null);
}
export declare const configurator: Configurator;
export {};
