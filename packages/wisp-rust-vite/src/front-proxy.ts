import { BlockList, connect as connectTcp, isIP } from "node:net";
import { randomBytes } from "node:crypto";
import { connect as connectTls } from "node:tls";

/**
 * Policy helpers for the Bun front: upstream URL construction, client identity, header
 * forwarding, WebSocket close codes and connection caps. They are kept apart from the proxy
 * loop so each one can be tested without a server.
 */

/** A request the front refuses to proxy, with the status to answer it with. */
export class ProxyRejection extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/**
 * Cloudflare's published edge ranges, from https://www.cloudflare.com/ips-v4 and
 * https://www.cloudflare.com/ips-v6. Refresh them from those pages when Cloudflare changes the
 * list. `WISP_FRONT_TRUSTED_EDGE_CIDRS`, a comma-separated list of addresses and CIDRs,
 * replaces them. Loopback is always trusted on top of whichever list is in force.
 */
export const CLOUDFLARE_EDGE_CIDRS = [
  "173.245.48.0/20",
  "103.21.244.0/22",
  "103.22.200.0/22",
  "103.31.4.0/22",
  "141.101.64.0/18",
  "108.162.192.0/18",
  "190.93.240.0/20",
  "188.114.96.0/20",
  "197.234.240.0/22",
  "198.41.128.0/17",
  "162.158.0.0/15",
  "104.16.0.0/13",
  "104.24.0.0/14",
  "172.64.0.0/13",
  "131.0.72.0/22",
  "2400:cb00::/32",
  "2606:4700::/32",
  "2803:f800::/32",
  "2405:b500::/32",
  "2405:8100::/32",
  "2a06:98c0::/29",
  "2c0f:f248::/32",
];

/** One spelling per address, so `::ffff:1.2.3.4` and `1.2.3.4` are the same client. */
export function canonicalIp(raw: string | null | undefined): string | null {
  const candidate = raw?.trim() ?? "";
  const family = isIP(candidate);
  if (family === 4) {
    return candidate
      .split(".")
      .map((part) => Number.parseInt(part, 10).toString(10))
      .join(".");
  }
  if (family !== 6) return null;
  let hostname: string;
  try {
    hostname = new URL(`http://[${candidate}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(hostname);
  if (!mapped) return hostname;
  const high = Number.parseInt(mapped[1] ?? "0", 16);
  const low = Number.parseInt(mapped[2] ?? "0", 16);
  return [high >> 8, high & 255, low >> 8, low & 255].join(".");
}

export function isLoopbackIp(address: string): boolean {
  return address === "::1" || address.startsWith("127.");
}

export type EdgeTrust = {
  edge: BlockList;
};

/** Parses `WISP_FRONT_TRUSTED_EDGE_CIDRS` style input, ignoring entries that are not ranges. */
export function createEdgeTrust(
  override: string | readonly string[] | undefined = process.env
    .WISP_FRONT_TRUSTED_EDGE_CIDRS,
): EdgeTrust {
  const configured = (
    typeof override === "string" ? override.split(",") : (override ?? [])
  )
    .map((entry) => entry.trim())
    .filter(Boolean);
  const edge = new BlockList();
  for (const entry of configured.length > 0
    ? configured
    : CLOUDFLARE_EDGE_CIDRS) {
    const [rawAddress, bits] = entry.split("/");
    const address = canonicalIp(rawAddress);
    const family = address ? isIP(address) : 0;
    if (!address || family === 0) {
      console.warn(`wisp-rust-vite: ignoring trusted edge range ${entry}`);
      continue;
    }
    const max = family === 6 ? 128 : 32;
    const prefix = bits === undefined ? max : Number.parseInt(bits, 10);
    if (!Number.isInteger(prefix) || prefix < 0 || prefix > max) {
      console.warn(`wisp-rust-vite: ignoring trusted edge range ${entry}`);
      continue;
    }
    if (bits === undefined) {
      edge.addAddress(address, family === 6 ? "ipv6" : "ipv4");
    } else {
      edge.addSubnet(address, prefix, family === 6 ? "ipv6" : "ipv4");
    }
  }
  return { edge };
}

/** Whether the TCP peer is Cloudflare, or this machine (Caddy and the origin mux). */
export function isTrustedEdgePeer(
  trust: EdgeTrust,
  peerAddress: string | null | undefined,
): boolean {
  const peer = canonicalIp(peerAddress);
  if (!peer) return false;
  if (isLoopbackIp(peer)) return true;
  return trust.edge.check(peer, isIP(peer) === 6 ? "ipv6" : "ipv4");
}

/**
 * The one client address everything behind the front sees. A connection from Cloudflare (or
 * from this machine, where Caddy sets the headers itself) is believed when it names a client in
 * `CF-Connecting-IP`; a loopback peer without one is believed through the last
 * `X-Forwarded-For` hop. Every other peer is its own client, so a connection that skipped
 * Cloudflare cannot choose its address. Returns null when there is no usable peer.
 */
export function resolveCanonicalClientIp(
  trust: EdgeTrust,
  peerAddress: string | null | undefined,
  headers: Headers,
): string | null {
  const peer = canonicalIp(peerAddress);
  if (!peer) return null;
  if (!isTrustedEdgePeer(trust, peer)) return peer;
  // Duplicated headers join with a comma, which is not an address, so they fall through
  const edgeClient = canonicalIp(headers.get("cf-connecting-ip"));
  if (edgeClient) return edgeClient;
  if (isLoopbackIp(peer)) {
    const forwarded = headers.get("x-forwarded-for");
    if (forwarded && forwarded.length <= 8192) {
      const hops = forwarded.split(",");
      if (hops.length <= 128) {
        for (let index = hops.length - 1; index >= 0; index -= 1) {
          const hop = canonicalIp(hops[index]);
          if (hop) return hop;
        }
      }
    }
  }
  return peer;
}

/** A random per-process secret shared with the native listener. */
export function generateEdgeSecret(): string {
  return randomBytes(32).toString("hex");
}

export const EDGE_SECRET_HEADER = "x-wisp-edge-secret";

/** Request headers the app is given. Everything else, including identity headers, is dropped. */
const FORWARDED_REQUEST_HEADERS = new Set([
  "accept",
  "accept-encoding",
  "accept-language",
  "access-control-request-headers",
  "access-control-request-method",
  "authorization",
  "cache-control",
  "content-encoding",
  "content-language",
  "content-length",
  "content-type",
  "cookie",
  "dnt",
  "if-match",
  "if-modified-since",
  "if-none-match",
  "if-range",
  "if-unmodified-since",
  "origin",
  "pragma",
  "priority",
  "purpose",
  "range",
  "referer",
  "save-data",
  "service-worker",
  "service-worker-navigation-preload",
  "upgrade-insecure-requests",
  "user-agent",
  "x-csrf-token",
  "x-requested-with",
  "x-xsrf-token",
]);
const FORWARDED_REQUEST_PREFIXES = ["sec-", "x-stellite-"];
/** Edge metadata that is only believed when it came from Cloudflare or this machine. */
const EDGE_METADATA_HEADERS = ["cf-ipcountry", "cf-ray", "cf-visitor"];

function extraForwardedHeaders(): Set<string> {
  return new Set(
    (process.env.WISP_FRONT_FORWARD_HEADERS ?? "")
      .split(",")
      .map((name) => name.trim().toLowerCase())
      .filter(Boolean),
  );
}

export type UpstreamHeaderInput = {
  clientIp: string;
  trustedPeer: boolean;
  publicHost: string;
  publicProtocol: string;
  extraAllowed?: ReadonlySet<string>;
};

/**
 * The headers sent to the app. Host is the vetted public host, and the client address is
 * written by this process alone: any `X-Real-IP`, `Forwarded`, `True-Client-IP` or forwarding
 * header the client supplied is dropped.
 */
export function buildUpstreamRequestHeaders(
  source: Headers,
  input: UpstreamHeaderInput,
): Headers {
  const extra = input.extraAllowed ?? extraForwardedHeaders();
  const headers = new Headers();
  for (const [name, value] of source) {
    const lower = name.toLowerCase();
    if (
      FORWARDED_REQUEST_HEADERS.has(lower) ||
      FORWARDED_REQUEST_PREFIXES.some((prefix) => lower.startsWith(prefix)) ||
      extra.has(lower)
    ) {
      headers.append(name, value);
    }
  }
  if (input.trustedPeer) {
    for (const name of EDGE_METADATA_HEADERS) {
      const value = source.get(name);
      if (value) headers.set(name, value);
    }
  }
  const forwardedProto = input.trustedPeer
    ? source.get("x-forwarded-proto")?.trim().toLowerCase()
    : undefined;
  headers.set("host", input.publicHost);
  headers.set("x-forwarded-host", input.publicHost);
  headers.set(
    "x-forwarded-proto",
    forwardedProto === "http" || forwardedProto === "https"
      ? forwardedProto
      : input.publicProtocol.replace(/:$/, ""),
  );
  headers.set("x-forwarded-for", input.clientIp);
  headers.set("cf-connecting-ip", input.clientIp);
  return headers;
}

const HOP_BY_HOP_RESPONSE_HEADERS = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

/** Response headers safe to relay: hop-by-hop headers belong to the upstream connection. */
export function filterUpstreamResponseHeaders(source: Headers): Headers {
  const headers = new Headers(source);
  const named = (source.get("connection") ?? "")
    .split(",")
    .map((token) => token.trim().toLowerCase())
    .filter(Boolean);
  for (const name of [...HOP_BY_HOP_RESPONSE_HEADERS, ...named]) {
    headers.delete(name);
  }
  return headers;
}

/** Headers sent on a native or app WebSocket upgrade. Only the origin and our identity pass. */
export function buildUpstreamSocketHeaders(input: {
  origin?: string | null;
  clientIp: string;
  edgeSecret?: string;
}): Record<string, string> {
  const headers: Record<string, string> = {};
  if (input.origin && !/[\r\n]/.test(input.origin)) {
    headers.Origin = input.origin;
  }
  headers["X-Forwarded-For"] = input.clientIp;
  headers["CF-Connecting-IP"] = input.clientIp;
  if (input.edgeSecret) headers[EDGE_SECRET_HEADER] = input.edgeSecret;
  return headers;
}

/** Whether a path would let a client pick the host once resolved against another URL. */
export function isAuthorityPath(pathname: string): boolean {
  return pathname.startsWith("//") || pathname.startsWith("/\\");
}

export type UpstreamScheme = "http" | "ws";

/**
 * The upstream URL for a request: the target's own origin with the request's path and query.
 * Nothing in the request can change the host, port or scheme, and the result is checked.
 */
export function buildUpstreamUrl(
  target: URL,
  pathname: string,
  search: string,
  scheme: UpstreamScheme = "http",
): URL {
  if (isAuthorityPath(pathname)) {
    throw new ProxyRejection(400, "Invalid request path");
  }
  const upstream = new URL(target.origin);
  upstream.pathname = pathname;
  upstream.search = search;
  if (scheme === "ws") {
    upstream.protocol =
      target.protocol === "https:" || target.protocol === "wss:" ? "wss:" : "ws:";
  }
  assertSameOrigin(upstream, target, scheme);
  return upstream;
}

/** Fails closed when an upstream URL does not point at the target it was built for. */
export function assertSameOrigin(
  upstream: URL,
  target: URL,
  scheme: UpstreamScheme = "http",
): void {
  const expectedProtocol =
    scheme === "ws"
      ? target.protocol === "https:" || target.protocol === "wss:"
        ? "wss:"
        : "ws:"
      : target.protocol;
  if (
    upstream.protocol !== expectedProtocol ||
    upstream.host !== target.host ||
    upstream.username !== "" ||
    upstream.password !== ""
  ) {
    throw new ProxyRejection(400, "Upstream origin mismatch");
  }
}

const MAX_CLOSE_REASON_BYTES = 123;

/**
 * A close code that may legally be sent on the wire. 1005 and 1006 only describe a close that
 * carried no code, so they are forwarded as a normal close.
 */
export function forwardableCloseCode(code: number): number {
  if (code === 1005 || code === 1006) return 1000;
  if (
    code === 1000 ||
    (code >= 1001 && code <= 1003) ||
    (code >= 1007 && code <= 1014) ||
    (code >= 3000 && code <= 4999)
  ) {
    return code;
  }
  return 1011;
}

/** A close reason cut to the 123 bytes a control frame can carry, on a character boundary. */
export function truncateCloseReason(reason: string | undefined): string {
  if (!reason) return "";
  let out = "";
  let bytes = 0;
  for (const char of reason) {
    const size = Buffer.byteLength(char);
    if (bytes + size > MAX_CLOSE_REASON_BYTES) break;
    out += char;
    bytes += size;
  }
  return out;
}

export type WebSocketSlot = { release(): void };

/**
 * Caps concurrent WebSockets in total and per canonical client address. A slot is taken before
 * the upstream connect starts, so connects that are still pending count too.
 */
export class WebSocketLimiter {
  private total = 0;
  private readonly perIp = new Map<string, number>();

  constructor(
    private readonly maxTotal: number,
    private readonly maxPerIp: number,
  ) {}

  acquire(clientIp: string): WebSocketSlot | "total" | "per-ip" {
    if (this.total >= this.maxTotal) return "total";
    const current = this.perIp.get(clientIp) ?? 0;
    if (current >= this.maxPerIp) return "per-ip";
    this.total += 1;
    this.perIp.set(clientIp, current + 1);
    let released = false;
    return {
      release: () => {
        if (released) return;
        released = true;
        this.total -= 1;
        const left = (this.perIp.get(clientIp) ?? 1) - 1;
        if (left <= 0) this.perIp.delete(clientIp);
        else this.perIp.set(clientIp, left);
      },
    };
  }

  get active(): number {
    return this.total;
  }
}

export function positiveIntegerEnv(name: string, fallback: number): number {
  const parsed = Number.parseInt(process.env[name]?.trim() ?? "", 10);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * Replays a refused WebSocket upgrade by hand to learn the HTTP status, which Bun's client
 * hides behind a generic failure. Only used after a failed connect, and the replay is closed as
 * soon as the status line arrives. Undefined when no status was read.
 */
export function probeUpstreamStatus(
  target: URL,
  request: {
    headers: Record<string, string>;
    protocols: readonly string[];
  },
  timeoutMs = 3000,
): Promise<number | undefined> {
  return new Promise((resolveStatus) => {
    const secure = target.protocol === "wss:" || target.protocol === "https:";
    const port = Number.parseInt(target.port, 10) || (secure ? 443 : 80);
    const host = target.hostname.replace(/^\[|\]$/g, "");
    const socket = secure
      ? connectTls({ host, port, servername: host })
      : connectTcp({ host, port });
    let settled = false;
    const done = (status: number | undefined) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolveStatus(status);
    };
    const timer = setTimeout(() => done(undefined), timeoutMs);
    const lines = [
      `GET ${target.pathname}${target.search} HTTP/1.1`,
      `Host: ${target.host}`,
      "Connection: Upgrade",
      "Upgrade: websocket",
      "Sec-WebSocket-Version: 13",
      `Sec-WebSocket-Key: ${randomBytes(16).toString("base64")}`,
    ];
    const protocols = request.protocols.filter((protocol) =>
      /^[\w.!#$%&'*+^`|~-]+$/.test(protocol),
    );
    if (protocols.length > 0) {
      lines.push(`Sec-WebSocket-Protocol: ${protocols.join(", ")}`);
    }
    for (const [name, value] of Object.entries(request.headers)) {
      if (/[\r\n]/.test(name) || /[\r\n]/.test(value)) continue;
      lines.push(`${name}: ${value}`);
    }
    socket.once(secure ? "secureConnect" : "connect", () => {
      socket.write(`${lines.join("\r\n")}\r\n\r\n`);
    });
    let received = "";
    socket.on("data", (chunk: Buffer) => {
      received += chunk.toString("latin1");
      if (received.includes("\r\n") || received.length > 256) {
        const match = /^HTTP\/1\.[01] (\d{3})/.exec(received);
        done(match ? Number.parseInt(match[1] ?? "", 10) : undefined);
      }
    });
    socket.on("error", () => done(undefined));
    socket.on("close", () => done(undefined));
  });
}

/** The status to answer a client with after its upstream refused the connection. */
export function mirroredRejectionStatus(status: number | undefined): number {
  return status !== undefined && status >= 400 && status <= 599 ? status : 502;
}
