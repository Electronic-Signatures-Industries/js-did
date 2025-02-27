import type { DagJWS } from './types';
export declare function encodeBase64(bytes: Uint8Array): string;
export declare function encodeBase64Url(bytes: Uint8Array): string;
export declare function decodeBase64(s: string): Uint8Array;
export declare function base64urlToJSON(s: string): Record<string, any>;
export declare function randomString(): string;
export declare function fromDagJWS(jws: DagJWS): string;
