import test from "node:test";
import assert from "node:assert/strict";
import { admissionResolver, checkTunnelDestination, createAdmissionResolver, type ResolveHost } from "../src/tunnel-guard.ts";

function countingResolve(ips: string[]) {
    const calls: string[] = [];
    const resolve: ResolveHost = async (host) => {
        calls.push(host);
        return ips;
    };
    return { resolve, calls };
}

function flakyResolve(ips: string[]) {
    const calls: string[] = [];
    const state = { fail: false };
    const resolve: ResolveHost = async (host) => {
        calls.push(host);
        if (state.fail) throw Object.assign(new Error("dns down"), { code: "EAI_AGAIN" });
        return ips;
    };
    return { resolve, calls, state };
}

test("admission resolver: one lookup serves every admission inside the TTL", async () => {
    let clock = 1_000;
    const { resolve, calls } = countingResolve(["10.1.2.3"]);
    const resolver = createAdmissionResolver({ systemResolve: resolve, ttlMs: 60_000, now: () => clock });

    assert.deepEqual(await resolver("gw.internal"), ["10.1.2.3"]);
    clock += 59_000;
    assert.deepEqual(await resolver("GW.Internal"), ["10.1.2.3"], "cache key is case-insensitive");
    assert.deepEqual(calls, ["gw.internal"], "second admission of the same host does not re-resolve");
    assert.equal(resolver.stats().hits, 1);

    clock += 2_000;
    assert.deepEqual(await resolver("gw.internal"), ["10.1.2.3"]);
    assert.deepEqual(calls, ["gw.internal", "gw.internal"], "expiry re-resolves");
});

test("admission resolver: ttlMs 0 leaves the lookup un-cached", async () => {
    const { resolve, calls } = countingResolve(["10.1.2.3"]);
    const resolver = createAdmissionResolver({ systemResolve: resolve, ttlMs: 0 });

    await resolver("gw.internal");
    await resolver("gw.internal");
    assert.equal(calls.length, 2);
    assert.equal(resolver.stats().hits, 0);
});

test("admission resolver: concurrent admissions share one in-flight lookup", async () => {
    let release: (ips: string[]) => void = () => {};
    const gate = new Promise<string[]>((r) => {
        release = r;
    });
    let calls = 0;
    const resolver = createAdmissionResolver({
        systemResolve: () => {
            calls++;
            return gate;
        },
    });

    const pending = [resolver("gw.internal"), resolver("gw.internal"), resolver("gw.internal")];
    assert.equal(calls, 1, "the later admissions joined the first lookup");

    release(["10.0.0.9"]);
    assert.deepEqual(await Promise.all(pending), [["10.0.0.9"], ["10.0.0.9"], ["10.0.0.9"]]);
    assert.equal(resolver.stats().coalesced, 2);
});

test("admission resolver: a failing resolver reuses the last good answer (stale-while-error)", async () => {
    let clock = 10_000;
    const { resolve, state } = flakyResolve(["10.9.8.7"]);
    const resolver = createAdmissionResolver({ systemResolve: resolve, ttlMs: 1_000, staleMs: 60_000, now: () => clock });

    assert.deepEqual(await resolver("gw.internal"), ["10.9.8.7"]);
    clock += 5_000;
    state.fail = true;
    assert.deepEqual(await resolver("gw.internal"), ["10.9.8.7"], "a resolver blip does not fail admission");
    assert.equal(resolver.stats().staleHits, 1);
    assert.equal(resolver.stats().failures, 1);
});

test("admission resolver: past the stale window the original error surfaces", async () => {
    let clock = 10_000;
    const { resolve, state } = flakyResolve(["10.9.8.7"]);
    const resolver = createAdmissionResolver({ systemResolve: resolve, ttlMs: 1_000, staleMs: 2_000, now: () => clock });

    await resolver("gw.internal");
    clock += 10_000;
    state.fail = true;
    await assert.rejects(async () => resolver("gw.internal"), (err: NodeJS.ErrnoException) => err.code === "EAI_AGAIN");
    assert.equal(resolver.stats().staleHits, 0);
});

test("admission resolver: .local names ask unicast DNS first instead of the mDNS path", async () => {
    let systemCalls = 0;
    const unicastCalls: string[] = [];
    const resolver = createAdmissionResolver({
        systemResolve: () => {
            systemCalls++;
            return new Promise<string[]>(() => {});
        },
        unicastResolve: async (host) => {
            unicastCalls.push(host);
            return ["172.29.165.61"];
        },
    });

    assert.deepEqual(await resolver("llm-gw.jd.local"), ["172.29.165.61"]);
    assert.deepEqual(unicastCalls, ["llm-gw.jd.local"]);
    assert.equal(systemCalls, 0, "the OS resolver (5s mDNS detour on macOS) is never started");
});

test("admission resolver: a .local name missing from unicast DNS still falls back to the OS resolver", async () => {
    const resolver = createAdmissionResolver({
        systemResolve: async () => ["192.168.1.7"],
        unicastResolve: async () => {
            throw Object.assign(new Error("not found"), { code: "ENOTFOUND" });
        },
    });

    assert.deepEqual(await resolver("nas.local"), ["192.168.1.7"]);
});

test("admission resolver: non-.local names never touch the unicast resolver", async () => {
    let unicastCalls = 0;
    const resolver = createAdmissionResolver({
        systemResolve: async () => ["8.8.8.8"],
        unicastResolve: async () => {
            unicastCalls++;
            return ["1.1.1.1"];
        },
    });

    assert.deepEqual(await resolver("api.example.com"), ["8.8.8.8"]);
    assert.equal(unicastCalls, 0);
});

test("admission resolver: the cache is bounded, destinations come from client input", async () => {
    const resolver = createAdmissionResolver({ systemResolve: async () => ["10.0.0.1"], maxEntries: 2 });

    await resolver("a.example");
    await resolver("b.example");
    await resolver("c.example");
    assert.equal(resolver.stats().entries, 2);
});

test("checkTunnelDestination: a warm admission cache keeps a private upstream admitted while the resolver is down", async () => {
    const { resolve, state } = flakyResolve(["10.1.2.3"]);
    const ctx = { selfPort: 8787, clientLoopback: true, allowlist: [] as string[], resolveHost: createAdmissionResolver({ systemResolve: resolve }), resolveBackoffMs: 0 };

    assert.deepEqual(await checkTunnelDestination("http://gw.internal:9100/v1", ctx), { ok: true });

    state.fail = true;
    assert.deepEqual(await checkTunnelDestination("http://gw.internal:9100/v1", ctx), { ok: true }, "the admission that used to 502 now rides the cached answer");
});

test("checkTunnelDestination: without a cached answer a failing resolver still denies", async () => {
    const failing: ResolveHost = async () => {
        throw Object.assign(new Error("dns down"), { code: "EAI_AGAIN" });
    };
    const ctx = { selfPort: 8787, clientLoopback: true, allowlist: [] as string[], resolveHost: createAdmissionResolver({ systemResolve: failing }), resolveBackoffMs: 0 };

    const verdict = await checkTunnelDestination("http://gw.internal:9100/v1", ctx);
    assert.equal(verdict.ok, false);
    assert.equal(verdict.ok === false && verdict.code, "unresolvable");
});

test("admission resolver: the module-level instance is a usable ResolveHost", async () => {
    assert.equal(typeof admissionResolver, "function");
    assert.equal(typeof admissionResolver.stats().misses, "number");
});
