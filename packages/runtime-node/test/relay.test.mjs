import { test } from "node:test";
import assert from "node:assert/strict";
import {
	sanitizeBrowserPayload,
	createBrowserRelayFetchHandler,
} from "../dist/index.js";

function sanitizeContext(context) {
	const out = sanitizeBrowserPayload({
		version: 1,
		service: "svc",
		environment: "test",
		events: [{ type: "message", timestamp: "t", context }],
	});
	assert.ok(out, "payload should be valid");
	return out.events[0].context;
}

test("relay: deeply nested context is bounded, not passed through raw", () => {
	let deep = "leaf";
	for (let i = 0; i < 30; i++) deep = { n: deep };
	const ctx = sanitizeContext(deep);
	assert.equal(typeof ctx, "object");
	assert.doesNotThrow(() => JSON.stringify(ctx));
});

test("relay: context strings are length-capped", () => {
	const ctx = sanitizeContext({ big: "x".repeat(9000) });
	assert.equal(ctx.big.length, 4000);
});

test("relay: context arrays are element-capped", () => {
	const ctx = sanitizeContext({ arr: Array.from({ length: 500 }, (_, i) => i) });
	assert.equal(ctx.arr.length, 100);
});

test("relay: cyclic context does not hang or throw", () => {
	const cyclic = { a: 1 };
	cyclic.self = cyclic;
	const ctx = sanitizeContext(cyclic);
	assert.equal(ctx.a, 1);
	assert.equal(ctx.self, undefined);
});

test("relay: non-serialisable context values are dropped", () => {
	const ctx = sanitizeContext({ fn: () => 1, keep: 2 });
	assert.equal(ctx.fn, undefined);
	assert.equal(ctx.keep, 2);
});

test("relay: revoked Proxy context is dropped without throwing", () => {
	const { proxy, revoke } = Proxy.revocable({ a: 1 }, {});
	revoke();
	assert.doesNotThrow(() => sanitizeContext(proxy));
});

test("relay: hostile Proxy length trap in context does not throw", () => {
	const hostile = new Proxy([], {
		get(_t, prop) {
			if (prop === "length") throw new Error("boom");
			return undefined;
		},
	});
	assert.doesNotThrow(() => sanitizeContext(hostile));
});

test("relay: hostile Proxy element getter in context does not throw", () => {
	const hostile = new Proxy([1, 2, 3], {
		get(target, prop) {
			if (prop === "0") throw new Error("boom");
			return target[prop];
		},
	});
	assert.doesNotThrow(() => sanitizeContext(hostile));
});

test("relay: fetch size limit counts UTF-8 bytes, not code units", async () => {
	const handler = createBrowserRelayFetchHandler({
		apiKey: "autter_rt_test",
		perIpRateLimit: false,
		maxBodyBytes: 10,
	});
	const body = "அ".repeat(6);
	assert.equal(body.length, 6);
	const res = await handler(
		new Request("http://localhost/relay", { method: "POST", body }),
	);
	assert.equal(res.status, 413);
});

test("relay: fetch handler rejects an oversized body", async () => {
	const handler = createBrowserRelayFetchHandler({
		apiKey: "autter_rt_test",
		perIpRateLimit: false,
		maxBodyBytes: 100,
	});
	const res = await handler(
		new Request("http://localhost/relay", {
			method: "POST",
			body: "a".repeat(500),
		}),
	);
	assert.equal(res.status, 413);
});

test("relay: secret-bearing context keys are redacted (top level and nested)", () => {
	const ctx = sanitizeContext({
		password: "hunter2",
		token: "abc",
		authorization: "Bearer x",
		request: { headers: { cookie: "sid=1", authorization: "Bearer victim" } },
		keep: "ok",
	});
	assert.equal(ctx.password, "[redacted]");
	assert.equal(ctx.token, "[redacted]");
	assert.equal(ctx.authorization, "[redacted]");
	assert.equal(ctx.request.headers.cookie, "[redacted]");
	assert.equal(ctx.request.headers.authorization, "[redacted]");
	assert.equal(ctx.keep, "ok");
});

test("relay: secret-shaped values under benign keys are scrubbed", () => {
	// Built at runtime so no JWT-shaped literal sits in source (would trip
	// secret scanners); the parts are meaningless placeholders.
	const jwtLike = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJ0ZXN0In0", "0".repeat(22)].join(".");
	const ctx = sanitizeContext({
		note: "Bearer supersecrettoken12345",
		jwtish: jwtLike,
		plain: "just a normal message",
	});
	assert.equal(ctx.note, "[redacted]");
	assert.equal(ctx.jwtish, "[redacted]");
	assert.equal(ctx.plain, "just a normal message");
});

test("relay: a truthy but non-true trustProxy stays on the safe shared bucket", async () => {
	const handler = createBrowserRelayFetchHandler({
		apiKey: "autter_rt_test",
		perIpRateLimit: 1,
		// a common config slip: an env string "false" is truthy but must NOT
		// enable forwarded-header trust
		trustProxy: "false",
	});
	const mk = (ip) =>
		new Request("http://localhost/relay", {
			method: "POST",
			headers: { "x-forwarded-for": ip },
			body: "{",
		});
	const first = await handler(mk("1.1.1.1"));
	const second = await handler(mk("2.2.2.2"));
	assert.equal(first.status, 400);
	assert.equal(second.status, 429); // shared bucket — not fooled by "false"
});

test("relay: numeric usage counts under token/session keys are preserved", () => {
	const ctx = sanitizeContext({
		input_tokens: 500,
		output_tokens: 1200,
		total_tokens: 1700,
		sessions: 3,
	});
	assert.deepEqual(ctx, {
		input_tokens: 500,
		output_tokens: 1200,
		total_tokens: 1700,
		sessions: 3,
	});
});

test("relay: spoofed X-Forwarded-For cannot bypass the rate limit by default", async () => {
	const handler = createBrowserRelayFetchHandler({
		apiKey: "autter_rt_test",
		perIpRateLimit: 1,
	});
	const mk = (ip) =>
		new Request("http://localhost/relay", {
			method: "POST",
			headers: { "x-forwarded-for": ip },
			body: "{",
		});
	const first = await handler(mk("1.1.1.1"));
	const second = await handler(mk("2.2.2.2"));
	assert.equal(first.status, 400); // passed rate limit, then invalid JSON
	assert.equal(second.status, 429); // shared bucket — spoofed IP can't bypass
});

test("relay: trustProxy honors distinct X-Forwarded-For buckets", async () => {
	const handler = createBrowserRelayFetchHandler({
		apiKey: "autter_rt_test",
		perIpRateLimit: 1,
		trustProxy: true,
	});
	const mk = (ip) =>
		new Request("http://localhost/relay", {
			method: "POST",
			headers: { "x-forwarded-for": ip },
			body: "{",
		});
	const a = await handler(mk("1.1.1.1"));
	const b = await handler(mk("2.2.2.2"));
	assert.notEqual(a.status, 429);
	assert.notEqual(b.status, 429);
});

test("relay: oversized body returns 413 even when cancel() never settles", async () => {
	const handler = createBrowserRelayFetchHandler({
		apiKey: "autter_rt_test",
		perIpRateLimit: false,
		maxBodyBytes: 10,
	});
	const big = new Uint8Array(100);
	const body = new ReadableStream({
		pull(controller) {
			controller.enqueue(big);
		},
		cancel() {
			return new Promise(() => {}); // never settles
		},
	});
	const res = await Promise.race([
		handler(
			new Request("http://localhost/relay", {
				method: "POST",
				body,
				duplex: "half",
			}),
		),
		new Promise((_, reject) =>
			setTimeout(() => reject(new Error("handler hung")), 2000),
		),
	]);
	assert.equal(res.status, 413);
});

test("relay: oversized body stays 413 even when the stream's cancel() rejects", async () => {
	const handler = createBrowserRelayFetchHandler({
		apiKey: "autter_rt_test",
		perIpRateLimit: false,
		maxBodyBytes: 10,
	});
	const big = new Uint8Array(100);
	const body = new ReadableStream({
		pull(controller) {
			controller.enqueue(big);
		},
		cancel() {
			// a hostile/broken stream whose cancel throws must not downgrade 413 to 400
			throw new Error("hostile cancel");
		},
	});
	const res = await handler(
		new Request("http://localhost/relay", {
			method: "POST",
			body,
			duplex: "half",
		}),
	);
	assert.equal(res.status, 413);
});

test("relay: fetch size limit allows a body within the byte budget", async () => {
	const handler = createBrowserRelayFetchHandler({
		apiKey: "autter_rt_test",
		perIpRateLimit: false,
	});
	const res = await handler(
		new Request("http://localhost/relay", { method: "POST", body: "{" }),
	);
	assert.equal(res.status, 400);
});
