import { get } from 'node:http';
export function isLocalDshRoot(url) {
    return url.protocol === 'http:' && ['127.0.0.1', '[::1]'].includes(url.hostname)
        && url.port !== '' && url.pathname === '/' && !url.search && !url.hash
        && !url.username && !url.password;
}
/** Redeem the host's normal launch URL without navigating Chromium or following redirects. */
export async function localDshGrant(rawUrl, getOrigin, authenticatedUrl, signal) {
    try {
        const base = new URL(rawUrl);
        if (!isLocalDshRoot(base) || new URL(getOrigin() ?? '').href !== base.href)
            return undefined;
        const launch = new URL(authenticatedUrl(base.href) ?? '');
        const tokens = launch.searchParams.getAll('token');
        if (tokens.length !== 1 || !tokens[0])
            throw new Error();
        launch.searchParams.delete('token');
        if (launch.href !== base.href)
            throw new Error();
        // No ambient proxy, no redirects, and no credential in an exception or URL history.
        launch.searchParams.set('token', tokens[0]);
        const deadline = AbortSignal.timeout(5_000);
        return await new Promise((resolve, reject) => {
            const req = get(launch, { agent: false, signal: signal ? AbortSignal.any([signal, deadline]) : deadline }, res => {
                const values = res.headers['set-cookie'] ?? [];
                const attrs = values.length === 1 ? values[0].split(';').map(part => part.trim()) : [];
                const [cookie = ''] = attrs;
                const age = Number(attrs.find(part => part.startsWith('Max-Age='))?.slice(8));
                // The installed Host emits a relative clean-root redirect. Never resolve or follow it.
                const location = res.headers.location;
                if (res.statusCode === 303 && location === './'
                    && validCookiePair(cookie) && Number.isSafeInteger(age) && age > 0
                    && attrs.includes('Path=/') && attrs.includes('HttpOnly') && attrs.includes('SameSite=Strict')
                    && !attrs.some(part => /^domain=/i.test(part))) {
                    resolve({ origin: base.origin, cookie, expiresAt: Date.now() + Math.min(age, 3600) * 1000 });
                }
                else {
                    reject(new Error());
                }
                res.destroy();
            });
            req.once('error', reject);
        });
    }
    catch (error) {
        signal?.throwIfAborted();
        // Ordinary unrelated navigation or a missing Host must not be turned into auth.
        // Invalid URLs fail in the regular navigation validator, not here.
        try {
            const target = new URL(rawUrl);
            if (!isLocalDshRoot(target) || new URL(getOrigin() ?? '').href !== target.href)
                return undefined;
        }
        catch {
            return undefined;
        }
        throw new Error('browser: local DSH sign-in failed');
    }
}
function validCookiePair(pair) {
    return /^[A-Za-z0-9_-]+=[A-Za-z0-9._~-]+$/.test(pair);
}
export function isLocalDshGrant(value) {
    const grant = value;
    try {
        return grant !== undefined && typeof grant.origin === 'string'
            && isLocalDshRoot(new URL(grant.origin)) && new URL(grant.origin).origin === grant.origin
            && typeof grant.cookie === 'string' && validCookiePair(grant.cookie)
            && typeof grant.expiresAt === 'number' && Number.isSafeInteger(grant.expiresAt)
            && grant.expiresAt > Date.now() && grant.expiresAt <= Date.now() + 3_600_000;
    }
    catch {
        return false;
    }
}
/** Constrain credential use more tightly than cookies, which are shared across ports. */
export function localDshHeaders(grant, rawUrl, resourceType, headers) {
    if (grant === undefined || grant.expiresAt <= Date.now())
        return headers;
    let url;
    try {
        url = new URL(rawUrl);
    }
    catch {
        return headers;
    }
    const origin = resourceType === 'webSocket' && url.protocol === 'ws:' ? `http://${url.host}` : url.origin;
    if (origin !== grant.origin)
        return headers;
    const keys = Object.keys(headers);
    const getHeader = (name) => headers[keys.find(key => key.toLowerCase() === name) ?? ''];
    const site = getHeader('sec-fetch-site');
    const requestOrigin = getHeader('origin');
    if (requestOrigin !== undefined && requestOrigin !== origin)
        return headers;
    if (resourceType === 'webSocket' ? requestOrigin !== origin
        : site !== 'same-origin' && !(site === 'none' && resourceType === 'mainFrame'))
        return headers;
    const key = keys.find(k => k.toLowerCase() === 'cookie') ?? 'Cookie';
    const name = grant.cookie.slice(0, grant.cookie.indexOf('='));
    const existing = (Array.isArray(headers[key]) ? headers[key].join(';') : headers[key] ?? '').split(';')
        .map(part => part.trim()).filter(part => part && !part.startsWith(`${name}=`));
    return { ...headers, [key]: [...existing, grant.cookie].join('; ') };
}
