import { ResolverOptions, DIDResolutionResult, ResolverRegistry, Resolver } from 'did-resolver';
import { JWE } from 'ifesa-did-jwt';
import type { DagJWS, DIDProvider } from './types';
export type { DIDResolutionResult } from 'did-resolver';
export * from './types';
export interface AuthenticateOptions {
    provider?: DIDProvider;
    aud?: string;
    paths?: Array<string>;
}
export interface AuthenticateParams {
    nonce: string;
    aud?: string;
    paths?: Array<string>;
}
export interface AuthenticateResponse extends AuthenticateParams {
    did: string;
    exp: number;
}
export interface CreateJWSOptions {
    did?: string;
    protected?: Record<string, any>;
    linkedBlock?: string;
}
export interface CreateJWSParams extends CreateJWSOptions {
    payload: any;
}
export interface CreateJWSResult {
    jws: DagJWS;
}
export interface VerifyJWSResult {
    kid: string;
    payload?: Record<string, any>;
    didResolutionResult: DIDResolutionResult;
}
export interface CreateJWEOptions {
    protectedHeader?: Record<string, any>;
    aad?: Uint8Array;
}
export interface DecryptJWEOptions {
    did?: string;
}
export interface DecryptJWEParams extends DecryptJWEOptions {
    jwe: JWE;
}
export interface DecryptJWEResult {
    cleartext: string;
}
export interface DagJWSResult {
    jws: DagJWS;
    linkedBlock: Uint8Array;
}
export interface DIDOptions {
    provider?: DIDProvider;
    resolver?: Resolver | ResolverRegistry;
    resolverOptions?: ResolverOptions;
}
export declare class DID {
    private _client?;
    private _id?;
    private _resolver;
    constructor({ provider, resolver, resolverOptions }?: DIDOptions);
    get authenticated(): boolean;
    get id(): string;
    setProvider(provider: DIDProvider): void;
    setResolver(resolver: Resolver | ResolverRegistry, resolverOptions?: ResolverOptions): void;
    authenticate({ provider, paths, aud }?: AuthenticateOptions): Promise<string>;
    createJWS<T = any>(payload: T, options?: CreateJWSOptions): Promise<DagJWS>;
    createDagJWS(payload: Record<string, any>, options?: CreateJWSOptions): Promise<DagJWSResult>;
    verifyJWS(jws: string | DagJWS): Promise<VerifyJWSResult>;
    createJWE(cleartext: Uint8Array, recipients: Array<string>, options?: CreateJWEOptions): Promise<JWE>;
    createDagJWE(cleartext: Record<string, any>, recipients: Array<string>, options?: CreateJWEOptions): Promise<JWE>;
    decryptJWE(jwe: JWE, options?: DecryptJWEOptions): Promise<Uint8Array>;
    decryptDagJWE(jwe: JWE): Promise<Record<string, any>>;
    resolve(didUrl: string): Promise<DIDResolutionResult>;
}
