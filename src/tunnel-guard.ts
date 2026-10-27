import { lookup, resolve4 } from "node:dns/promises";
import { networkInterfaces } from "node:os";

/**
 * Tunnel admission for the `/bili/<absolute-url>` zero-config branch (#409).
 *
 * The CONNECT/MITM side has destination admission (mitm.ts — whitelisted
 * hosts, loopback-only blind tunnels). The /bili/ absolute-URL side had none:
 * it would happily forward to the proxy's OWN /__bili/ management plane (the
 * inner connection originates from the proxy, so the loopback admin gate
 * passes), to link-local metadata addresses, or — on a `--host 0.0.0.0`
 * deployment — to anything reachable from this machine, turning bili into a
 * LAN-reachable SSRF pivot despite the "management stays loopback-only"
 * promise.
 *
 * Policy (destination × client):
 *   - the proxy itself (same port, own addresses incl. 127/8) → always deny
 *   - link-local / metadata ranges → always deny (no legitimate use through
 *     a model-traffic tunnel)
 *   - loopback/private destinations → allowed for loopback clients (the
 *     self-hosted-upstream case: sglang on 127.0.0.1:8199, ollama on
 *     11434, a LAN relay — the httpRewrites launcher flow DEPENDS on this),
 *     denied for remote clients unless the destination is on the explicit
 *     allowlist (BILI_TUNNEL_ALLOWED_HOSTS, "host" or "host:port" entries)
 *   - public destinations → allowed
 *
 * Hostnames are resolved before the verdict (an attacker must not bypass the
 * range checks with "metadata.google.internal" or a rebind-friendly name);
 * unresolvable names are denied outright. A DNS-rebinding race between the
 * check and the connect remains theoretically possible and accepted — the
 * `x-bili-tunnel` marker + management-plane rejection below is the second
 * layer that still holds when it happens.
 *
 * #1686: the admission lookup is bounded-retried (3 attempts, short backoff,
 * per-attempt timeout) because a transiently unreachable DNS server must not
 * be indistinguishable from a genuinely dead name — and the caller answers a
 * resolution failure with 5xx (transport-class), never 403 (permission-class),
 * so clients keep their retry logic alive while the resolver recovers.
 */

// #1686: admission-resolution budget. Per-attempt timeout because a dead OS
// resolver can otherwise hang getaddrinfo for tens of seconds (Windows);
// worst-case total admission delay ≈ 3 × RESOLVE_TIMEOUT_MS + 2 × backoff.
const RESOLVE_MAX_ATTEMPTS = 3;
const RESOLVE_BACKOFF_MS = 250;
const RESOLVE_TIMEOUT_MS = 2000;

// Admission results are cached: the same upstream host is re-admitted on every
// /bili/ request, and a lookup that misses every time turns one slow resolver
// into a permanent 502 loop instead of a single retry. A cached answer also
// outlives a resolver blip (stale-while-error), which is what "the local
// resolver may be unreachable" in the 502 message is actually describing.
const RESOLVE_CACHE_TTL_MS = 60_000;
const RESOLVE_STALE_MS = 10 * 60_000;
const RESOLVE_CACHE_MAX_ENTRIES = 512;
// .local is resolved by mDNS first on macOS (resolver timeout 5s) before the
// unicast answer is tried — longer than the per-attempt budget, so those names
// get an explicit unicast query instead.
const MDNS_SUFFIX = ".local";

export const BILI_TUNNEL_HEADER = "x-bili-tunnel";

type IpClass = "loopback" | "linkLocal" | "private" | "public";

/** Parse a v4 quad or v6 literal (incl. ::ffff: mapped); null for names. */
export function parseIpLiteral(s: string): string | null {
    const t = s.trim().toLowerCase();
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(t)) return t;
    if (t.includes(":")) return t; // v6 literal (possibly mapped); names never contain ':'
    return null;
}

/** IPv4-mapped v6 in ANY form → the plain dotted quad: both the dotted
 *  `::ffff:1.2.3.4` and the HEX form `::ffff:102:304` the WHATWG URL parser
 *  canonicalizes hostnames to (`new URL("http://[::ffff:127.0.0.1]/")` yields
 *  `[::ffff:7f00:1]`), which otherwise sails past every dotted-only matcher.
 *  Range classification and self-membership then see one shape. */
export function normalizeIpLiteral(ip: string): string {
    const t = ip.trim().toLowerCase();
    if (!t.startsWith("::ffff:")) return t;
    const dotted = t.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (dotted) return dotted[1];
    const hex = t.match(/^::ffff:0*([0-9a-f]{1,4}):0*([0-9a-f]{1,4})$/);
    if (hex) {
        const hi = parseInt(hex[1], 16);
        const lo = parseInt(hex[2], 16);
        return `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
    }
    return t;
}

export function classifyIp(ip: string): IpClass {
    const lit = normalizeIpLiteral(parseIpLiteral(ip) ?? "");
    if (!lit) return "public";
    if (lit.includes(":")) {
        if (lit === "::1" || lit === "::") return "loopback";
        if (lit.startsWith("fe8") || lit.startsWith("fe9") || lit.startsWith("fea") || lit.startsWith("feb")) return "linkLocal";
        if (lit.startsWith("fc") || lit.startsWith("fd")) return "private"; // fc00::/7 ULA
        return "public";
    }
    const parts = lit.split(".").map(Number);
    const [a, b] = parts;
    if (a === 127) return "loopback";
    if (a === 169 && b === 254) return "linkLocal";
    if (a === 10 || a === 0) return "private";
    if (a === 172 && b >= 16 && b <= 31) return "private";
    if (a === 192 && b === 168) return "private";
    if (a === 100 && b >= 64 && b <= 127) return "private"; // CGNAT shared space
    return "public";
}

export type ResolveHost = (host: string) => Promise<string[]>;

// The native lookup({timeout}) option exists at runtime (Node ≥ 15.3) but is
// missing from @types/node's LookupOptions — race instead of casting. The
// losing lookup stays handled (Promise.race subscribes to both sides), so a
// late OS-resolver failure cannot surface as an unhandled rejection.
function withDeadline<T>(work: Promise<T>, ms: number): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error("ETIMEDOUT"), { code: "ETIMEDOUT" })), ms);
        timer.unref?.();
    });
    return Promise.race([work, deadline]).finally(() => {
        if (timer) clearTimeout(timer);
    });
}

const dnsResolveHost: ResolveHost = async (host) =>
    (await withDeadline(lookup(host, { all: true, family: 0 }), RESOLVE_TIMEOUT_MS)).map((r) => r.address);

// c-ares unicast query: no getaddrinfo, no mDNS detour, no OS resolver state.
// A-record only — the tunnel connects to one of these addresses, and an
// AAAA-only destination still has the system resolver as its fallback.
const dnsResolveUnicast: ResolveHost = (host) => withDeadline(resolve4(host), RESOLVE_TIMEOUT_MS);

export interface AdmissionResolverOptions {
    /** System (getaddrinfo) resolution — the existing behavior. */
    systemResolve?: ResolveHost;
    /** Unicast (c-ares) resolution tried first for mDNS-prone names. */
    unicastResolve?: ResolveHost;
    /** Successful answers are reused for this long (0 disables the cache). */
    ttlMs?: number;
    /** A last-known-good answer may be reused this long after a failed lookup (0 disables). */
    staleMs?: number;
    /** Upper bound on cached hosts — destinations come from client input. */
    maxEntries?: number;
    now?: () => number;
}

export interface AdmissionResolverStats {
    hits: number;
    staleHits: number;
    misses: number;
    coalesced: number;
    failures: number;
    entries: number;
}

export interface AdmissionResolver extends ResolveHost {
    stats(): AdmissionResolverStats;
}

/**
 * Cache + single-flight + stale-while-error around the admission lookup, with a
 * unicast-first path for names the OS resolver sends to mDNS first.
 */
export function createAdmissionResolver(opts: AdmissionResolverOptions = {}): AdmissionResolver {
    const systemResolve = opts.systemResolve ?? dnsResolveHost;
    const unicastResolve = opts.unicastResolve ?? dnsResolveUnicast;
    const ttlMs = opts.ttlMs ?? RESOLVE_CACHE_TTL_MS;
    const staleMs = opts.staleMs ?? RESOLVE_STALE_MS;
    const maxEntries = opts.maxEntries ?? RESOLVE_CACHE_MAX_ENTRIES;
    const now = opts.now ?? Date.now;
    const cache = new Map<string, { ips: string[]; at: number }>();
    const inflight = new Map<string, Promise<string[]>>();
    const counters = { hits: 0, staleHits: 0, misses: 0, coalesced: 0, failures: 0 };

    const resolveFresh = async (host: string): Promise<string[]> => {
        if (host.replace(/\.$/, "").endsWith(MDNS_SUFFIX)) {
            try {
                const ips = await unicastResolve(host);
                if (ips.length > 0) return ips;
            } catch {
                // Not in unicast DNS (a real mDNS name, or an /etc/hosts entry):
                // the system resolver is the only path that can still answer.
            }
        }
        return systemResolve(host);
    };

    const admit = async (host: string): Promise<string[]> => {
        const key = host.toLowerCase();
        const cached = cache.get(key);
        if (ttlMs > 0 && cached && now() - cached.at < ttlMs) {
            counters.hits++;
            return cached.ips.slice();
        }
        const running = inflight.get(key);
        if (running) {
            counters.coalesced++;
            return running;
        }
        counters.misses++;
        const attempt = (async () => {
            try {
                const ips = await resolveFresh(host);
                if (ips.length > 0) {
                    if (maxEntries > 0 && !cache.has(key) && cache.size >= maxEntries) {
                        const oldest = cache.keys().next();
                        if (!oldest.done) cache.delete(oldest.value);
                    }
                    cache.set(key, { ips: ips.slice(), at: now() });
                }
                return ips;
            } catch (err) {
                counters.failures++;
                const last = cache.get(key);
                if (staleMs > 0 && last && now() - last.at < staleMs) {
                    counters.staleHits++;
                    return last.ips.slice();
                }
                throw err;
            } finally {
                inflight.delete(key);
            }
        })();
        inflight.set(key, attempt);
        return attempt;
    };

    return Object.assign(admit, { stats: (): AdmissionResolverStats => ({ ...counters, entries: cache.size }) });
}

export const admissionResolver = createAdmissionResolver();

export function admissionResolveStats(): AdmissionResolverStats {
    return admissionResolver.stats();
}

let localAddrCache: { at: number; ips: Set<string> } | undefined;
/** All addresses considered "this machine": 127/8 + ::1 + every interface unicast addr. */
export function localMachineIps(): Set<string> {
    const now = Date.now();
    if (!localAddrCache || now - localAddrCache.at > 30_000) {
        const ips = new Set<string>(["127.0.0.1", "::1"]);
        for (const list of Object.values(networkInterfaces())) {
            for (const ni of list ?? []) {
                if (ni.address) ips.add(ni.address.toLowerCase());
            }
        }
        // The whole 127/8 loopback range routes to this machine.
        for (let i = 0; i <= 255; i++) ips.add(`127.0.0.${i}`);
        localAddrCache = { at: now, ips };
    }
    return localAddrCache.ips;
}

interface TunnelCheckContext {
    /** Port this proxy is actually serving on (server.address()). */
    selfPort: number | undefined;
    clientLoopback: boolean;
    allowlist: string[];
    resolveHost?: ResolveHost;
    localIps?: () => Set<string>;
    /** Backoff between admission-resolution retries (default RESOLVE_BACKOFF_MS). */
    resolveBackoffMs?: number;
    /**
     * #2124: this destination's egress leaves through an upstream proxy, which
     * resolves it REMOTELY (CONNECT \x3chost\x3e:\x3cport\x3e) — bili never sees the IP, so
     * classifying a hostname against the local resolver measured the wrong object
     * and a polluted/unreachable resolver hard-denied valid public destinations.
     * Hostnames are then delegated to the proxy (no local classification); IP
     * literals and direct-egress hostnames are unaffected.
     */
    egressProxied?: boolean;
}

type TunnelVerdict = { ok: true } | { ok: false; code: "self" | "linkLocal" | "privateRemote" | "unresolvable" | "invalid"; message: string };

function allowlistHit(host: string, port: number, allowlist: string[]): boolean {
    const h = host.toLowerCase();
    const hp = `${h}:${port}`;
    return allowlist.some((e) => e === h || e === hp);
}

export async function checkTunnelDestination(origin: string, ctx: TunnelCheckContext): Promise<TunnelVerdict> {
    let u: URL;
    try {
        u = new URL(origin);
    } catch {
        return { ok: false, code: "invalid", message: `invalid tunnel destination ${origin}` };
    }
    const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    const port = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
    let ips: string[];
    const literal = parseIpLiteral(host);
    if (literal) {
        ips = [normalizeIpLiteral(literal)];
    } else if (ctx.egressProxied) {
        // #2124: egress leaves through an upstream proxy, which resolves the
        // destination REMOTELY (CONNECT \x3chost\x3e:\x3cport\x3e) — bili never sees the IP, so
        // local-resolver classification measured the wrong object and hard-denied
        // valid public names under a polluted/unreachable resolver. Delegate to the
        // proxy; the x-bili-tunnel marker + management-plane rejection still blocks
        // reaching the proxy's own /__bili/ plane.
        return { ok: true };
    } else {
        // #1686: bounded retry — a transiently unreachable DNS server must not
        // masquerade as a dead name. Only throws are retried; an empty answer
        // is definitive (the resolver said so).
        const resolve = ctx.resolveHost ?? admissionResolver;
        const backoff = ctx.resolveBackoffMs ?? RESOLVE_BACKOFF_MS;
        let resolved: string[] | undefined;
        let lastErrCode: string | undefined;
        for (let attempt = 1; attempt <= RESOLVE_MAX_ATTEMPTS; attempt++) {
            try {
                resolved = await resolve(host);
                break;
            } catch (err) {
                const code = (err as { code?: string } | null)?.code;
                if (code) lastErrCode = code;
                if (attempt === RESOLVE_MAX_ATTEMPTS) break;
                await new Promise<void>((r) => setTimeout(r, backoff));
            }
        }
        if (resolved === undefined) return {
            ok: false,
            code: "unresolvable",
            message: `cannot resolve tunnel destination ${host}${lastErrCode ? ` (${lastErrCode})` : ""}: local name resolution failed — the local resolver may be unreachable or taken over by another DNS service (VPN/MagicDNS); route egress through an upstream proxy to have the destination resolved remotely`,
        };
        ips = resolved;
        if (ips.length === 0) return { ok: false, code: "unresolvable", message: `no addresses for tunnel destination ${host}` };
        // #2143: mDNS names (.local / single-label) answer with an unreachable
        // fe80:: AAAA beside the routable A record. A bare fe80:: has no zone
        // scope, so it can never be a connect target — safe to drop ONLY when a
        // non-link-local answer coexists; a pure link-local answer keeps its
        // hard deny in Layer 2. Hostname path only; IP literals skip this.
        if (ips.some((ip) => classifyIp(ip) === "linkLocal") && ips.some((ip) => classifyIp(ip) !== "linkLocal")) {
            ips = ips.filter((ip) => classifyIp(ip) !== "linkLocal");
        }
    }
    // Layer 1: the proxy itself — the /__bili/ management plane must never be
    // reachable through the tunnel, from any client. 0.0.0.0/:: as a
    // destination routes to the local host, so our own port through them is
    // a self-loop even though neither literal sits in the interface set.
    if (ctx.selfPort !== undefined && port === ctx.selfPort) {
        const mine = (ctx.localIps ?? localMachineIps)();
        if (ips.some((ip) => ip === "0.0.0.0" || ip === "::" || mine.has(ip.toLowerCase()) || mine.has(`::ffff:${ip.toLowerCase()}`))) {
            return { ok: false, code: "self", message: "the bili tunnel may not target the proxy itself" };
        }
    }
    // Layer 2: link-local / metadata — no legitimate model upstream lives there.
    const classes = ips.map((ip) => classifyIp(ip));
    if (classes.includes("linkLocal")) {
        return { ok: false, code: "linkLocal", message: "link-local / metadata destinations are blocked from the bili tunnel" };
    }
    // Layer 3: loopback / private — fine for local clients (self-hosted
    // upstreams), denied for remote clients unless explicitly allowlisted.
    if (!classes.every((c) => c === "public")) {
        if (ctx.clientLoopback) return { ok: true };
        if (allowlistHit(host, port, ctx.allowlist)) return { ok: true };
        return {
            ok: false,
            code: "privateRemote",
            message: `tunnel destination ${host} resolves to a loopback/private address; remote clients may only reach it via BILI_TUNNEL_ALLOWED_HOSTS`,
        };
    }
    return { ok: true };
}

/** Parse BILI_TUNNEL_ALLOWED_HOSTS ("host" / "host:port", comma-separated). */
export function tunnelAllowlistFromEnv(env: NodeJS.ProcessEnv = process.env): string[] {
    const raw = env.BILI_TUNNEL_ALLOWED_HOSTS ?? "";
    return raw
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter((s) => s.length > 0);
}
