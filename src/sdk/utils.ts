export type DeferredPromise<T> = {
    promise: Promise<T>;
    resolve: (value: T) => void;
    reject: Function;
};

export function createDeferredPromise<T = void>(): DeferredPromise<T> {
    const rv = {} as DeferredPromise<T>;
    rv.promise = new Promise((_resolve, _reject) => {
        rv.resolve = _resolve;
        rv.reject = _reject;
    });
    return rv;
}

export function ajax2<T>(method: string, url: string, data?: Record<string, string>): Promise<T> {
    const response = fetch(url, {
        method: method,
        headers: {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: data ? new URLSearchParams(data) : undefined
    });
    return response.then(r => r.json());
}

export async function ajax<T>(method: string, url: string, data?: Record<string, string>): Promise<T> {
    const response = await fetch(url, {
        method: method,
        headers: {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: data ? new URLSearchParams(data) : undefined
    });
    const json = await response.json();
    return json;
}

export function ajax0<T>(method: string, url: string, data?: Record<string, string>): Promise<T> {
    const promise = new Promise<T>(
        function (resolve, reject) {
            const xhr = new XMLHttpRequest();
            xhr.open(method, url, true);
            xhr.responseType = "json";
            xhr.setRequestHeader("Accept", "application/json");
            xhr.onreadystatechange =
                function onreadystatechange() {
                    if (this.readyState === XMLHttpRequest.DONE) {
                        if (this.status === 200) {
                            let data;
                            if (this.responseType === '' && typeof this.responseText === "string")
                                data = JSON.parse(this.responseText);
                            else
                                data = this.response;
                            resolve(data);
                        } else {
                            reject(this);
                        }
                    }
                };

            if (method.toLowerCase() === "post" && data) {
                var urlEncodedData = "";
                var urlEncodedDataPairs = [];
                var name;
                for (name in data) {
                    urlEncodedDataPairs.push(`${encodeURIComponent(name)}=${encodeURIComponent(data[name])}`);
                }
                urlEncodedData = urlEncodedDataPairs.join('&').replace(/%20/g, '+');
                xhr.send(urlEncodedData);
            } else {
                xhr.send();
            }
        });
    return promise;
}

export class FixedQueue {
    private m_items: any[] = [];
    private m_maxSize: number;

    constructor(maxSize: number) {
        this.m_items = [];
        this.m_maxSize = maxSize;
    }
    trimHead() {
        if (this.m_items.length > this.m_maxSize) {
            this.m_items.splice(0, this.m_items.length - this.m_maxSize);
        }
    }
    trimTail() {
        if (this.m_items.length > this.m_maxSize) {
            this.m_items.splice(this.m_maxSize, this.m_items.length - this.m_maxSize);
        }
    }
    push(...args: any[]) {
        this.m_items.push(...args);
        this.trimHead();
    }
    splice(start: number, deleteCount?: number | undefined) {
        const result = this.m_items.splice(start, deleteCount);
        this.trimTail();
        return result;
    }
    unshift(...args: any[]) {
        const result = this.m_items.unshift(...args);
        this.trimTail();
        return result;
    }
    get length(): number {
        return this.m_items.length;
    }
    get items(): any[] {
        return this.m_items;
    }
}
