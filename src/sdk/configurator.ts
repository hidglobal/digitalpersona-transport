/**
* Loads configuration parameters from configuration server and saves it in session storage.
*/
import { envSdk, traceSdk } from './channel-definitions';
import { sjcl } from '../libs/index';
import { ajax } from './utils';

const SESSIONSTORAGE_CONNECTION_STR_KEY: string = "websdk"; // sessionStorage connection string
const SESSIONSTORAGE_SESSION_ID_KEY: string = "websdk.sessionId"; // sessionStorage session ID

/*
// Response from 'https://127.0.0.1:52181/get_connection':
// {"endpoint": "https://127.0.0.1:9001/?web_sdk_id=88436d25-94e4-4dff-9495-d1eacc1bf363&web_sdk_minport=9001&web_sdk_port=9001&web_sdk_secure=true&web_sdk_username=x6Lsn3u8Z14&web_sdk_password=270AD8A85B4EC070&web_sdk_salt=E3DC74D8FB769D7D9C052D80342E158361BF91CB7144DBE5AB15B8A550823898"}
"
https://127.0.0.1:9001/?
web_sdk_id=88436d25-94e4-4dff-9495-d1eacc1bf363
&web_sdk_minport=9001
&web_sdk_port=9001
&web_sdk_secure=true
&web_sdk_username=x6Lsn3u8Z14
&web_sdk_password=270AD8A85B4EC070
&web_sdk_salt=E3DC74D8FB769D7D9C052D80342E158361BF91CB7144DBE5AB15B8A550823898
"
// Session storage data
{
    "port":9001,
    "host":"127.0.0.1",
    "isSecure":true,
    "srp":{
        "p1":"L-3_YNKvdgs",
        "p2":"31B866CC4C0587C8",
        "salt":"77354DE2DD5A9126F693187E99CEFFCE8967269C28F710795C79714202CBDFB6"
    }
}
*/

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

type SRPDpHostData = {
    hostname: string;         // = "127.0.0.1" // for now it is always "127.0.0.1"
    web_sdk_port: string;     // = "web_sdk_port=9001"
    web_sdk_secure: string;   // = "web_sdk_secure=true"
    web_sdk_username: string; // = "web_sdk_username=L-3_YNKvdgs"
    web_sdk_password: string; // = "web_sdk_password=31B866CC4C0587C8"
    web_sdk_salt: string;     // = "web_sdk_salt=77354DE2DD5A9126F693187E99CEFFCE8967269C28F710795C79714202CBDFB6"
    // these values are sent back from 'get_connection' request, but not used here:
    web_sdk_id: string;       // = "88436d25-94e4-4dff-9495-d1eacc1bf363"
    web_sdk_minport: string;  // = "9001"
};

export type ErrorOrDataResult<T = string> = { error?: string, data?: T; };

class Configurator {
    public session: SRPSessionData = {
        port: 0,
        host: "127.0.0.1",
        secure: true,
        srpClient: null,
    };

    constructor() {
        try {
            const storageStr = sessionStorage.getItem(SESSIONSTORAGE_CONNECTION_STR_KEY);
            const sessionData: SRPSessionData = storageStr && JSON.parse(storageStr);
            if (sessionData) {
                this.session = sessionData;
            }
        } catch (error) {
        }
    }

    public async ensureLoaded(): Promise<ErrorOrDataResult> {
        try {
            if (this.session.port && this.session.host && this.session.srpClient) {
                return {};
            }
            const response = await ajax<{ endpoint: string; }>('get', 'https://127.0.0.1:52181/get_connection');
            if (this.parseHostReply(response?.endpoint)) {
                return {};
            }
        } catch (error) {
        }
        return { error: 'Cannot load configuration' };
    }

    private parseHostReply(connectionString: string | undefined): boolean {
        const sd = getSRPSessionData(connectionString);
        if (!sd) {
            return false;
        }
        this.session = sd;
        sessionStorage.setItem(SESSIONSTORAGE_CONNECTION_STR_KEY, JSON.stringify(sd));
        return true;

        function getSRPSessionData(connectionString: string | undefined): SRPSessionData | undefined {
            const co = parseConnectionString(connectionString);
            if (!co) {
                return;
            }
            const sd: SRPSessionData = {
                host: co.hostname,
                port: parseInt(co.web_sdk_port || ''),
                secure: co.web_sdk_secure === "true",
                srpClient: {
                    p1: co.web_sdk_username,
                    p2: co.web_sdk_password,
                    salt: co.web_sdk_salt,
                },
            };
            if (sd.port && sd.host && sd.srpClient?.p1 && sd.srpClient.p2 && sd.srpClient.salt) {
                return sd;
            }

            function parseConnectionString(str?: string): SRPDpHostData | undefined {
                traceSdk(`Configurator: DpHost string: "${str}"`);
                if (str) {
                    const [_host, rest] = str.split('?');
                    const params = (`hostname=127.0.0.1&${rest}`.split('&') || []);
                    return Object.fromEntries(params.map((param) => param.split('=')));
                }
            }
        }
    }

    public getDpHostConnectionUrl(): string {
        const { port, host, secure } = this.session;
        if (!port || !host) {
            throw new Error('No connection url');
        }
        const newUrl = `${secure ? 'https' : 'http'}://${host}:${port.toString()}`;
        return `${newUrl}/connect`;
    }

    public getDpAgentConnectionUrl({ dpAgentChannelId, M1 = 'no.M1' }: { dpAgentChannelId: string, M1: string | undefined; }): string {
        const { port, host, secure } = this.session;
        if (!port || !host || !this.session.srpClient) {
            throw new Error('No port,host,srpClient');
        }
        const newUrl = `${secure ? 'https' : 'http'}://${host}:${port.toString()}`;

        let sessionId = this.sessionId;
        if (!sessionId) {
            this.sessionId = sessionId = sjcl.codec.hex.fromBits(sjcl.random.randomWords(2, 0));
        }

        let connectionUrl = `${newUrl.replace('http', 'ws')}/${dpAgentChannelId}?username=${this.session.srpClient.p1}&M1=${M1}`;
        connectionUrl += `&sessionId=${this.sessionId}`;
        connectionUrl += `&version=${envSdk.version.toString()}`;

        return connectionUrl;
    }

    public get sessionId(): string | null {
        return sessionStorage.getItem(SESSIONSTORAGE_SESSION_ID_KEY);
    }

    public set sessionId(value: string | null) {
        if (!value) {
            sessionStorage.removeItem(SESSIONSTORAGE_SESSION_ID_KEY);
        } else {
            sessionStorage.setItem(SESSIONSTORAGE_SESSION_ID_KEY, value);
        }
    }
}

export const configurator = new Configurator();
