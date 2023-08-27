export function createDeferredPromise() {
    const rv = {};
    rv.promise = new Promise((_resolve, _reject) => {
        rv.resolve = _resolve;
        rv.reject = _reject;
    });
    return rv;
}
export function ajax(method, url, data) {
    const promise = new Promise(function (resolve, reject) {
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
                    }
                    else {
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
        }
        else {
            xhr.send();
        }
    });
    return promise;
}
export class FixedQueue {
    constructor(maxSize) {
        this.m_items = [];
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
    push(...args) {
        this.m_items.push(...args);
        this.trimHead();
    }
    splice(start, deleteCount) {
        const result = this.m_items.splice(start, deleteCount);
        this.trimTail();
        return result;
    }
    unshift(...args) {
        const result = this.m_items.unshift(...args);
        this.trimTail();
        return result;
    }
    get length() {
        return this.m_items.length;
    }
    get items() {
        return this.m_items;
    }
}
