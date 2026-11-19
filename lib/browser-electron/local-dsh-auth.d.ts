/** An owner cookie held in memory by the standalone Electron carrier, never by a page. */
export interface LocalDshGrant {
    readonly origin: string;
    readonly cookie: string;
    readonly expiresAt: number;
}
export declare function isLocalDshRoot(url: URL): boolean;
/** Redeem the host's normal launch URL without navigating Chromium or following redirects. */
export declare function localDshGrant(rawUrl: string, getOrigin: () => string | undefined, authenticatedUrl: (base: string) => string | undefined, signal?: AbortSignal): Promise<LocalDshGrant | undefined>;
export declare function isLocalDshGrant(value: unknown): value is LocalDshGrant;
/** Constrain credential use more tightly than cookies, which are shared across ports. */
export declare function localDshHeaders(grant: LocalDshGrant | undefined, rawUrl: string, resourceType: string, headers: Record<string, string | string[]>): Record<string, string | string[]>;
