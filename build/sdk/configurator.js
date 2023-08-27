/**
* Loads configuration parameters from configuration server and saves it in session storage.
*/
import { envSdk, traceSdk } from './channel-definitions';
import { sjcl } from 'ts-srpclient';
import { ajax } from './utils';
const SESSIONSTORAGE_CONNECTION_STR_KEY = "websdk"; // sessionStorage connection string
const SESSIONSTORAGE_SESSION_ID_KEY = "websdk.sessionId"; // sessionStorage session ID
class Configurator {
    constructor() {
        this.session = {
            port: 0,
            host: "127.0.0.1",
            secure: true,
            srpClient: null,
        };
        try {
            const storageStr = sessionStorage.getItem(SESSIONSTORAGE_CONNECTION_STR_KEY);
            const sessionData = storageStr && JSON.parse(storageStr);
            if (sessionData) {
                this.session = sessionData;
            }
        }
        catch (error) {
        }
    }
    async ensureLoaded() {
        try {
            if (this.session.port && this.session.host && this.session.srpClient) {
                return {};
            }
            const response = await ajax('get', 'https://127.0.0.1:52181/get_connection');
            if (this.parseHostReply(response?.endpoint)) {
                return {};
            }
        }
        catch (error) {
        }
        return { error: 'Cannot load configuration' };
    }
    parseHostReply(connectionString) {
        const sd = getSRPSessionData(connectionString);
        if (!sd) {
            return false;
        }
        this.session = sd;
        sessionStorage.setItem(SESSIONSTORAGE_CONNECTION_STR_KEY, JSON.stringify(sd));
        return true;
        function getSRPSessionData(connectionString) {
            const co = parseConnectionString(connectionString);
            if (!co) {
                return;
            }
            const sd = {
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
            function parseConnectionString(str) {
                traceSdk(`Configurator: DpHost string: "${str}"`);
                if (str) {
                    const [_host, rest] = str.split('?');
                    const params = (`hostname=127.0.0.1&${rest}`.split('&') || []);
                    return Object.fromEntries(params.map((param) => param.split('=')));
                }
            }
        }
    }
    getDpHostConnectionUrl() {
        const { port, host, secure } = this.session;
        if (!port || !host) {
            throw new Error('No connection url');
        }
        const newUrl = `${secure ? 'https' : 'http'}://${host}:${port.toString()}`;
        return `${newUrl}/connect`;
    }
    getDpAgentConnectionUrl({ dpAgentChannelId, M1 = 'no.M1' }) {
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
    get sessionId() {
        return sessionStorage.getItem(SESSIONSTORAGE_SESSION_ID_KEY);
    }
    set sessionId(value) {
        if (!value) {
            sessionStorage.removeItem(SESSIONSTORAGE_SESSION_ID_KEY);
        }
        else {
            sessionStorage.setItem(SESSIONSTORAGE_SESSION_ID_KEY, value);
        }
    }
}
export const configurator = new Configurator();
