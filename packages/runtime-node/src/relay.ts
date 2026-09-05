import type { IncomingMessage, ServerResponse } from "node:http";

/**
 * Same-origin browser relay. The browser tracker posts to a route on the
 * customer's own backend; this handler validates + sanitises the payload,
 * attaches the private ingest key server-side, forwards asynchronously to
 * the Autter ingester, and returns 202 immediately. The key never reaches
 * the browser, and there is no CORS/CSP surface.
 */

export interface RelayOptions {
	/** Private ingest key (autter_rt_…). Keep it in an env var. */
	apiKey: string;
	/** Ingester base URL. Default: https://otlp.autter.dev */
	endpoint?: string;
	/** Max accepted request body. Default 64 KB. */
	maxBodyBytes?: number;
	/**
	 * The relay route is necessarily public (browsers must reach it), so it
	 * ships with a per-IP fixed-window limit. Default 120 req/min; set
	 * `false` to disable (e.g. when a WAF already rate-limits).
	 */
	perIpRateLimit?: number | false;
	/**
	 * Trust the client-supplied `X-Forwarded-For` header when keying the per-IP
	 * rate limit. Off by default: the header is spoofable, so an attacker could
	 * rotate it to bypass the window and drive unbounded parsing/forwarding
	 * under the server's ingest key. Enable ONLY behind a proxy/CDN you control
	 * that overwrites the header. When off, the fetch handler keys a single
	 * shared bucket, and the Node handler keys the real socket peer address.
	 * Only a strict boolean `true` enables it — a truthy string such as the
	 * common `process.env.TRUST_PROXY === "false"` slip stays on the safe path.
	 */
	trustProxy?: boolean;
	/** Called when the async forward fails (default: console.warn). */
	onError?: (err: unknown) => void;
}

class IpWindow {
	private windows = new Map<string, { start: number; count: number }>();

	constructor(private readonly limitPerMinute: number) {}

	allow(ip: string): boolean {
		const start = Math.floor(Date.now() / 60_000) * 60_000;
		const entry = this.windows.get(ip);
		if (!entry || entry.start !== start) {
			this.windows.set(ip, { start, count: 1 });
			if (this.windows.size > 50_000) this.windows.clear();
			return true;
		}
		entry.count += 1;
		return entry.count <= this.limitPerMinute;
	}
}

function firstForwardedFor(value: string | string[] | undefined | null): string {
	const raw = Array.isArray(value) ? value[0] : value;
	return raw ? (raw.split(",")[0] ?? "").trim() : "";
}

const DEFAULT_ENDPOINT = "https://otlp.autter.dev";
const DEFAULT_MAX_BODY = 64 * 1024;
const MAX_EVENTS = 50;

const EVENT_TYPES = new Set([
	"exception",
	"unhandled_rejection",
	"message",
	"session_start",
	"track_event",
]);

const SEVERITIES = new Set(["fatal", "error", "warning", "info"]);

// Bound a browser-supplied `context` object so it honors the sanitiser's
// guarantee that a client can't smuggle unbounded cookies/DOM/bodies through
// the relay: like every other field, context is capped — bounded depth, a
// total-node budget, per-string length, and array/key limits. Cycles and
// throwing/revoked Proxy traps fail open (that value is dropped, sanitising
// continues).
const CONTEXT_MAX_DEPTH = 6;
const CONTEXT_MAX_NODES = 256;
const CONTEXT_MAX_STRING = 4000;
const CONTEXT_MAX_ARRAY = 100;
const CONTEXT_MAX_KEYS = 100;

// Redaction — the relay attaches the server's private ingest key and forwards
// browser-supplied context into privileged telemetry, so context must never
// carry secrets. We redact on two axes, at every nesting level: by KEY NAME
// (authorization, cookie, token, password, *_secret, *_key, session, jwt, …)
// and by secret-shaped VALUE (Bearer/Basic auth strings, JWTs) even under a
// benign/custom key. Numeric/boolean values under a matched key are kept —
// they can never be a credential, and this preserves usage counts such as
// `input_tokens`.
const REDACTED = "[redacted]";
const SECRET_KEY_RE =
	/(password|passwd|pwd|passphrase|passcode|secret|token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|private[_-]?key|authorization|cookie|session[_-]?id|sessionid|session|credentials?|bearer|jwt|otp|x-api-key|signature)/i;
const SECRET_VALUE_RE = /^\s*(bearer|basic)\s+\S+/i;
const JWT_RE = /\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]+/;

/** Redact a string that looks like a credential (auth header value / JWT). */
function scrubSecretValue(s: string): string {
	return SECRET_VALUE_RE.test(s) || JWT_RE.test(s) ? REDACTED : s;
}

/** UTF-8 byte length of a string (portable across edge runtimes). */
export function byteLength(text: string): number {
	return new TextEncoder().encode(text).length;
}

/**
 * Bounded, cycle-safe deep copy of an untrusted `context` value. Anything
 * past a depth/node/length limit, a cycle, or a hostile/revoked Proxy (whose
 * trap throws on classification, `length`, key enumeration, or element reads)
 * is dropped. Never throws — returns a plain, bounded object.
 */
export function boundContext(value: unknown): unknown {
	let nodes = 0;
	const seen = new WeakSet<object>();
	const walk = (v: unknown, depth: number): unknown => {
		if (v === null) return null;
		const t = typeof v;
		if (t === "string") return scrubSecretValue((v as string).slice(0, CONTEXT_MAX_STRING));
		if (t === "number" || t === "boolean") return v;
		if (t !== "object") return undefined;
		if (depth >= CONTEXT_MAX_DEPTH || nodes >= CONTEXT_MAX_NODES) return undefined;
		const obj = v as object;
		if (seen.has(obj)) return undefined;
		seen.add(obj);
		// Array.isArray can throw on a revoked Proxy — guard the classification.
		let isArr = false;
		try {
			isArr = Array.isArray(v);
		} catch {
			return undefined;
		}
		if (isArr) {
			const arr = v as unknown[];
			const out: unknown[] = [];
			// `length` can be a throwing/hostile trap — guard the read.
			let len = 0;
			try {
				len = arr.length;
			} catch {
				return out;
			}
			for (let i = 0; i < len && i < CONTEXT_MAX_ARRAY; i++) {
				if (nodes >= CONTEXT_MAX_NODES) break;
				nodes++;
				let el: unknown;
				try {
					el = walk(arr[i], depth + 1);
				} catch {
					el = undefined;
				}
				if (el !== undefined) out.push(el);
			}
			return out;
		}
		let keys: string[];
		try {
			keys = Object.keys(obj);
		} catch {
			return undefined;
		}
		const out: Record<string, unknown> = {};
		for (let i = 0; i < keys.length && i < CONTEXT_MAX_KEYS; i++) {
			if (nodes >= CONTEXT_MAX_NODES) break;
			const key = keys[i];
			if (key === undefined) continue;
			nodes++;
			// Redact secret-bearing keys at any depth. Numeric/boolean values
			// can't be credentials and are preserved (e.g. usage counts); any
			// other value (string, nested object/array) is dropped entirely.
			if (SECRET_KEY_RE.test(key)) {
				let raw: unknown;
				try {
					raw = (obj as Record<string, unknown>)[key];
				} catch {
					out[key] = REDACTED;
					continue;
				}
				const rt = typeof raw;
				out[key] = rt === "number" || rt === "boolean" ? raw : REDACTED;
				continue;
			}
			let child: unknown;
			try {
				child = walk((obj as Record<string, unknown>)[key], depth + 1);
			} catch {
				child = undefined;
			}
			if (child !== undefined) out[key] = child;
		}
		return out;
	};
	let result: unknown;
	try {
		result = walk(value, 0);
	} catch {
		result = undefined;
	}
	return result && typeof result === "object" ? result : {};
}

/**
 * Read a fetch `Request` body while enforcing `maxBody` as it is consumed,
 * counting real UTF-8 bytes from the byte stream (so multibyte payloads are
 * measured correctly). An oversized body is rejected as soon as the limit is
 * crossed — the stream is cancelled instead of being fully buffered first.
 */
async function readBodyBounded(
	request: Request,
	maxBody: number,
): Promise<{ tooLarge: true } | { tooLarge: false; text: string }> {
	const body = request.body;
	if (!body) {
		// No readable stream to meter — fall back to a buffered read + byte check.
		const text = await request.text();
		return byteLength(text) > maxBody
			? { tooLarge: true }
			: { tooLarge: false, text };
	}
	const reader = body.getReader();
	const chunks: Uint8Array[] = [];
	let total = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		if (!value) continue;
		total += value.byteLength;
		if (total > maxBody) {
			// Cancel is fire-and-forget: awaiting a cancel() that throws,
			// rejects, or never settles would hang the response (or drop it to
			// a 400). The oversize decision is already made — detach the cancel
			// and return 413 immediately.
			void Promise.resolve()
				.then(() => reader.cancel())
				.catch(() => {});
			return { tooLarge: true };
		}
		chunks.push(value);
	}
	const buf = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		buf.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return { tooLarge: false, text: new TextDecoder().decode(buf) };
}

// Whitelist sanitiser — anything not listed here is dropped, so a
// compromised or buggy client can't smuggle cookies/DOM/bodies through the
// relay. Returns null when the payload is structurally invalid.
export function sanitizeBrowserPayload(raw: unknown): object | null {
	if (typeof raw !== "object" || raw === null) return null;
	const p = raw as Record<string, unknown>;
	if (p.version !== 1) return null;
	if (typeof p.service !== "string" || !p.service) return null;
	if (typeof p.environment !== "string" || !p.environment) return null;
	if (!Array.isArray(p.events) || p.events.length > MAX_EVENTS) return null;

	const events: object[] = [];
	for (const rawEvent of p.events) {
		if (typeof rawEvent !== "object" || rawEvent === null) return null;
		const e = rawEvent as Record<string, unknown>;
		if (typeof e.type !== "string" || !EVENT_TYPES.has(e.type)) return null;
		if (typeof e.timestamp !== "string") return null;
		events.push({
			type: e.type,
			timestamp: e.timestamp,
			...(typeof e.severity === "string" && SEVERITIES.has(e.severity)
				? { severity: e.severity }
				: {}),
			message:
				typeof e.message === "string" ? e.message.slice(0, 4000) : "",
			...(typeof e.name === "string" ? { name: e.name.slice(0, 200) } : {}),
			...(typeof e.stack === "string"
				? { stack: e.stack.slice(0, 32000) }
				: {}),
			...(typeof e.errorType === "string"
				? { errorType: e.errorType.slice(0, 200) }
				: {}),
			...(typeof e.filename === "string"
				? { filename: e.filename.split("?")[0]!.slice(0, 1000) }
				: {}),
			...(typeof e.line === "number" ? { line: e.line } : {}),
			...(typeof e.column === "number" ? { column: e.column } : {}),
			...(typeof e.route === "string"
				? { route: e.route.split("?")[0]!.slice(0, 1000) }
				: {}),
			...(typeof e.context === "object" && e.context !== null
				? { context: boundContext(e.context) }
				: {}),
		});
	}

	return {
		version: 1,
		...(typeof p.sessionId === "string"
			? { sessionId: p.sessionId.slice(0, 100) }
			: {}),
		service: p.service.slice(0, 200),
		environment: p.environment.slice(0, 100),
		...(typeof p.release === "string"
			? { release: p.release.slice(0, 200) }
			: {}),
		events,
	};
}

function forward(payload: object, opts: RelayOptions): void {
	const url = `${(opts.endpoint ?? DEFAULT_ENDPOINT).replace(/\/$/, "")}/v1/browser`;
	void fetch(url, {
		method: "POST",
		headers: {
			"content-type": "application/json",
			authorization: `Bearer ${opts.apiKey}`,
		},
		body: JSON.stringify(payload),
		signal: AbortSignal.timeout(10_000),
	}).catch((err) => {
		(opts.onError ?? ((e) => console.warn("autter relay forward failed:", e)))(
			err,
		);
	});
}

/**
 * Fetch-style handler (Next.js App Router route, Remix, Hono, Bun, Deno):
 *
 *   export const POST = createBrowserRelayFetchHandler({ apiKey: env.AUTTER_RUNTIME_KEY });
 */
export function createBrowserRelayFetchHandler(
	opts: RelayOptions,
): (request: Request) => Promise<Response> {
	const maxBody = opts.maxBodyBytes ?? DEFAULT_MAX_BODY;
	const limiter =
		opts.perIpRateLimit === false
			? null
			: new IpWindow(opts.perIpRateLimit ?? 120);
	return async (request: Request): Promise<Response> => {
		if (request.method !== "POST") {
			return new Response(null, { status: 405 });
		}
		if (limiter) {
			// Only honor X-Forwarded-For behind an explicitly trusted proxy —
			// otherwise a caller could spoof a fresh IP per request to bypass
			// the window. With no trusted peer source in a fetch runtime, fall
			// back to one shared bucket (a conservative global limit).
			const ip =
				opts.trustProxy === true
					? firstForwardedFor(request.headers.get("x-forwarded-for")) ||
						"unknown"
					: "shared";
			if (!limiter.allow(ip)) {
				return new Response(JSON.stringify({ error: "rate limit exceeded" }), {
					status: 429,
				});
			}
		}
		let bounded: { tooLarge: true } | { tooLarge: false; text: string };
		try {
			bounded = await readBodyBounded(request, maxBody);
		} catch {
			return new Response(JSON.stringify({ error: "invalid json" }), {
				status: 400,
			});
		}
		if (bounded.tooLarge) {
			return new Response(JSON.stringify({ error: "payload too large" }), {
				status: 413,
			});
		}
		let raw: unknown;
		try {
			raw = JSON.parse(bounded.text);
		} catch {
			return new Response(JSON.stringify({ error: "invalid json" }), {
				status: 400,
			});
		}
		const payload = sanitizeBrowserPayload(raw);
		if (!payload) {
			return new Response(JSON.stringify({ error: "invalid payload" }), {
				status: 400,
			});
		}
		forward(payload, opts);
		return new Response(null, { status: 202 });
	};
}

/**
 * Node http / Express / Fastify(raw) handler:
 *
 *   app.post("/api/autter-runtime", createBrowserRelayHandler({ apiKey: process.env.AUTTER_RUNTIME_KEY! }));
 *
 * Works with or without a body parser: uses `req.body` when a middleware
 * already parsed it, otherwise reads the raw stream (capped).
 */
export function createBrowserRelayHandler(
	opts: RelayOptions,
): (
	req: IncomingMessage & { body?: unknown },
	res: ServerResponse,
) => void {
	const maxBody = opts.maxBodyBytes ?? DEFAULT_MAX_BODY;
	const limiter =
		opts.perIpRateLimit === false
			? null
			: new IpWindow(opts.perIpRateLimit ?? 120);

	function respond(res: ServerResponse, status: number, body?: object): void {
		res.statusCode = status;
		if (body) {
			res.setHeader("content-type", "application/json");
			res.end(JSON.stringify(body));
		} else {
			res.end();
		}
	}

	function handleParsed(raw: unknown, res: ServerResponse): void {
		const payload = sanitizeBrowserPayload(raw);
		if (!payload) {
			respond(res, 400, { error: "invalid payload" });
			return;
		}
		forward(payload, opts);
		respond(res, 202);
	}

	return (req, res) => {
		if (req.method !== "POST") {
			respond(res, 405);
			return;
		}
		if (limiter) {
			// Prefer the real socket peer; only trust X-Forwarded-For when the
			// caller has explicitly opted into a trusted-proxy deployment.
			const ip =
				(opts.trustProxy === true
					? firstForwardedFor(req.headers["x-forwarded-for"])
					: "") ||
				req.socket?.remoteAddress ||
				"unknown";
			if (!limiter.allow(ip)) {
				respond(res, 429, { error: "rate limit exceeded" });
				return;
			}
		}
		if (req.body !== undefined) {
			let raw: unknown = req.body;
			if (typeof raw === "string" || Buffer.isBuffer(raw)) {
				try {
					raw = JSON.parse(raw.toString());
				} catch {
					respond(res, 400, { error: "invalid json" });
					return;
				}
			}
			handleParsed(raw, res);
			return;
		}
		const chunks: Buffer[] = [];
		let size = 0;
		let aborted = false;
		req.on("data", (chunk: Buffer) => {
			size += chunk.length;
			if (size > maxBody) {
				aborted = true;
				respond(res, 413, { error: "payload too large" });
				req.destroy();
				return;
			}
			chunks.push(chunk);
		});
		req.on("end", () => {
			if (aborted) return;
			try {
				handleParsed(JSON.parse(Buffer.concat(chunks).toString()), res);
			} catch {
				respond(res, 400, { error: "invalid json" });
			}
		});
		req.on("error", () => {
			if (!aborted) respond(res, 400, { error: "read error" });
		});
	};
}
