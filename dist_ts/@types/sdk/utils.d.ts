export type DeferredPromise<T> = {
    promise: Promise<T>;
    resolve: (value: T) => void;
    reject: Function;
};
export declare function createDeferredPromise<T = void>(): DeferredPromise<T>;
export declare function ajax<T>(method: string, url: string, data?: Record<string, string>): Promise<T>;
export declare class FixedQueue {
    private m_items;
    private m_maxSize;
    constructor(maxSize: number);
    trimHead(): void;
    trimTail(): void;
    push(...args: any[]): void;
    splice(start: number, deleteCount?: number | undefined): any[];
    unshift(...args: any[]): number;
    get length(): number;
    get items(): any[];
}
