import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { parse as parseToml } from "smol-toml";
import {
  ProxyRejection,
  WebSocketLimiter,
  buildUpstreamRequestHeaders,
  buildUpstreamUrl,
  createEdgeTrust,
  filterUpstreamResponseHeaders,
  forwardableCloseCode,
  resolveCanonicalClientIp,
  truncateCloseReason,
} from "./front-proxy.js";
import { serveWispRustBunProxy } from "./index.js";
import type { WispRustBunProxy, WispRustNativeModule } from "./index.js";

describe("upstream URLs", () => {
  const target = new URL("http://127.0.0.1:3003");

  test("builds from the target origin", () => {
    const url = buildUpstreamUrl(target, "/a/b", "?x=1");
    expect(url.href).toBe("http://127.0.0.1:3003/a/b?x=1");
  });

  test("rejects paths that name an authority", () => {
    for (const path of ["//evil.example/x", "//127.0.0.1:9/", "/\\evil.example"]) {
      expect(() => buildUpstreamUrl(target, path, "")).toThrow(ProxyRejection);
    }
  });

  test("websocket urls keep the target host and swap the scheme", () => {
    expect(buildUpstreamUrl(target, "/ws", "", "ws").href).toBe(
      "ws://127.0.0.1:3003/ws",
    );
    expect(
      buildUpstreamUrl(new URL("https://app.test"), "/ws", "", "ws").protocol,
    ).toBe("wss:");
    expect(
      buildUpstreamUrl(new URL("wss://127.0.0.1:4142/wisp/"), "/wisp", "", "ws")
        .protocol,
    ).toBe("wss:");
  });
});

describe("client address", () => {
  const trust = createEdgeTrust(undefined);

  test("believes CF-Connecting-IP from a Cloudflare peer", () => {
    const headers = new Headers({ "cf-connecting-ip": "203.0.113.9" });
    expect(resolveCanonicalClientIp(trust, "173.245.48.5", headers)).toBe(
      "203.0.113.9",
    );
    expect(resolveCanonicalClientIp(trust, "2606:4700::1", headers)).toBe(
      "203.0.113.9",
    );
  });

  test("ignores forwarding headers from any other peer", () => {
    const headers = new Headers({
      "cf-connecting-ip": "203.0.113.9",
      "x-forwarded-for": "203.0.113.10",
    });
    expect(resolveCanonicalClientIp(trust, "198.51.100.7", headers)).toBe(
      "198.51.100.7",
    );
  });

  test("falls back to the peer for a malformed or duplicated header", () => {
    expect(
      resolveCanonicalClientIp(
        trust,
        "173.245.48.5",
        new Headers({ "cf-connecting-ip": "not-an-ip" }),
      ),
    ).toBe("173.245.48.5");
    const duplicated = new Headers();
    duplicated.append("cf-connecting-ip", "203.0.113.9");
    duplicated.append("cf-connecting-ip", "203.0.113.10");
    expect(resolveCanonicalClientIp(trust, "173.245.48.5", duplicated)).toBe(
      "173.245.48.5",
    );
  });

  test("trusts a loopback peer, which is where Caddy and the mux connect from", () => {
    expect(
      resolveCanonicalClientIp(
        trust,
        "::ffff:127.0.0.1",
        new Headers({ "cf-connecting-ip": "203.0.113.9" }),
      ),
    ).toBe("203.0.113.9");
    expect(
      resolveCanonicalClientIp(
        trust,
        "127.0.0.1",
        new Headers({ "x-forwarded-for": "1.1.1.1, 203.0.113.9" }),
      ),
    ).toBe("203.0.113.9");
  });

  test("the range list can be replaced", () => {
    const custom = createEdgeTrust("192.0.2.0/24");
    const headers = new Headers({ "cf-connecting-ip": "203.0.113.9" });
    expect(resolveCanonicalClientIp(custom, "192.0.2.4", headers)).toBe(
      "203.0.113.9",
    );
    expect(resolveCanonicalClientIp(custom, "173.245.48.5", headers)).toBe(
      "173.245.48.5",
    );
  });
});

describe("headers", () => {
  test("request headers are allowlisted and identity is rewritten", () => {
    const headers = buildUpstreamRequestHeaders(
      new Headers({
        accept: "text/html",
        connection: "keep-alive, x-hop",
        "x-hop": "1",
        "x-real-ip": "6.6.6.6",
        forwarded: "for=6.6.6.6",
        "true-client-ip": "6.6.6.6",
        "x-forwarded-for": "6.6.6.6",
        "cf-connecting-ip": "6.6.6.6",
        "x-wisp-edge-secret": "guess",
        "x-stellite-archive-client": "kept",
        cookie: "a=b",
      }),
      {
        clientIp: "203.0.113.9",
        trustedPeer: false,
        publicHost: "stellite.games",
        publicProtocol: "http:",
        extraAllowed: new Set(),
      },
    );
    expect(headers.get("accept")).toBe("text/html");
    expect(headers.get("cookie")).toBe("a=b");
    expect(headers.get("x-stellite-archive-client")).toBe("kept");
    expect(headers.get("host")).toBe("stellite.games");
    expect(headers.get("x-forwarded-for")).toBe("203.0.113.9");
    expect(headers.get("cf-connecting-ip")).toBe("203.0.113.9");
    for (const name of [
      "connection",
      "x-hop",
      "x-real-ip",
      "forwarded",
      "true-client-ip",
      "x-wisp-edge-secret",
    ]) {
      expect(headers.has(name)).toBe(false);
    }
  });

  test("edge metadata only passes from a trusted peer", () => {
    const source = new Headers({ "cf-ipcountry": "US", "x-forwarded-proto": "https" });
    const input = {
      clientIp: "203.0.113.9",
      publicHost: "stellite.games",
      publicProtocol: "http:",
      extraAllowed: new Set<string>(),
    };
    const trusted = buildUpstreamRequestHeaders(source, { ...input, trustedPeer: true });
    expect(trusted.get("cf-ipcountry")).toBe("US");
    expect(trusted.get("x-forwarded-proto")).toBe("https");
    const untrusted = buildUpstreamRequestHeaders(source, { ...input, trustedPeer: false });
    expect(untrusted.has("cf-ipcountry")).toBe(false);
    expect(untrusted.get("x-forwarded-proto")).toBe("http");
  });

  test("response hop-by-hop headers are dropped", () => {
    const headers = filterUpstreamResponseHeaders(
      new Headers({
        connection: "x-private",
        "x-private": "1",
        "transfer-encoding": "chunked",
        "content-encoding": "gzip",
        "content-type": "text/plain",
      }),
    );
    expect(headers.has("connection")).toBe(false);
    expect(headers.has("x-private")).toBe(false);
    expect(headers.has("transfer-encoding")).toBe(false);
    expect(headers.get("content-encoding")).toBe("gzip");
  });
});

describe("close codes", () => {
  test("only codes that can be sent are forwarded", () => {
    expect(forwardableCloseCode(1005)).toBe(1000);
    expect(forwardableCloseCode(1006)).toBe(1000);
    for (const code of [1000, 1001, 1002, 1003, 1007, 1011, 1013, 1014, 3000, 4999]) {
      expect(forwardableCloseCode(code)).toBe(code);
    }
    for (const code of [0, 999, 1004, 1015, 1016, 2999, 5000]) {
      expect(forwardableCloseCode(code)).toBe(1011);
    }
  });

  test("reasons fit a control frame", () => {
    expect(Buffer.byteLength(truncateCloseReason("é".repeat(200)))).toBeLessThanOrEqual(123);
    expect(truncateCloseReason(undefined)).toBe("");
  });
});

describe("websocket limiter", () => {
  test("caps total and per address, and frees slots", () => {
    const limiter = new WebSocketLimiter(3, 2);
    const a1 = limiter.acquire("1.1.1.1");
    const a2 = limiter.acquire("1.1.1.1");
    expect(limiter.acquire("1.1.1.1")).toBe("per-ip");
    const b1 = limiter.acquire("2.2.2.2");
    expect(limiter.acquire("3.3.3.3")).toBe("total");
    if (typeof a1 === "string" || typeof a2 === "string" || typeof b1 === "string") {
      throw new Error("expected slots");
    }
    a1.release();
    a1.release();
    expect(limiter.active).toBe(2);
    expect(typeof limiter.acquire("1.1.1.1")).toBe("object");
    a2.release();
    b1.release();
  });
});

describe("front proxy", () => {
  type Seen = { headers: Headers; url: string };
  const appSeen: Seen[] = [];
  const nativeSeen: Seen[] = [];
  let decoyHits = 0;
  let decoy: ReturnType<typeof Bun.serve>;
  let app: ReturnType<typeof Bun.serve>;
  let native: ReturnType<typeof Bun.serve>;
  let front: WispRustBunProxy;
  let nativeToml = "";
  const rawTcp = async (head: string): Promise<string> => {
    let received = "";
    const socket = await Bun.connect({
      hostname: "127.0.0.1",
      port: front.server.port ?? 0,
      socket: {
        data(_socket, chunk) {
          received += chunk.toString("latin1");
        },
      },
    });
    socket.write(head);
    await Bun.sleep(300);
    socket.end();
    return received;
  };

  beforeAll(async () => {
    decoy = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch() {
        decoyHits += 1;
        return new Response("decoy");
      },
    });
    app = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(request, server) {
        const url = new URL(request.url);
        appSeen.push({ headers: request.headers, url: request.url });
        if (url.pathname === "/gz") {
          return new Response(Bun.gzipSync("hello hello hello hello"), {
            headers: { "content-encoding": "gzip", "content-type": "text/plain" },
          });
        }
        if (url.pathname === "/ws" && server.upgrade(request, { data: undefined })) {
          return undefined;
        }
        return new Response("app");
      },
      websocket: { message() {} },
    });
    native = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch(request, server) {
        const url = new URL(request.url);
        nativeSeen.push({ headers: request.headers, url: request.url });
        if (url.searchParams.get("reject")) {
          return new Response("no", {
            status: Number(url.searchParams.get("reject")),
          });
        }
        const upgraded = server.upgrade(request, {
          data: undefined,
          headers: { "Sec-WebSocket-Protocol": "wisp-v1" },
        });
        return upgraded ? undefined : new Response("expected websocket", { status: 400 });
      },
      websocket: {
        message(socket, message) {
          socket.send(message);
        },
      },
    });
    const fakeNative = {
      WispRust: {
        fromToml(toml: string) {
          nativeToml = toml;
          return {
            start: async () => ({}),
            stop: async () => ({}),
            boundUrls: () => [`ws://127.0.0.1:${native.port}/wisp/`],
          };
        },
      },
    } as unknown as WispRustNativeModule;
    front = await serveWispRustBunProxy({
      native: fakeNative,
      toml: '[wisp.client]\nparse_real_ip_from = ["10.0.0.0/8"]\n',
      appTarget: `http://127.0.0.1:${app.port}`,
      hostname: "127.0.0.1",
      port: 0,
      stopOnSignals: false,
    });
  });

  afterAll(async () => {
    await front.stop();
    for (const server of [decoy, app, native]) await server.stop(true);
  });

  const frontUrl = (path: string) => `http://127.0.0.1:${front.server.port}${path}`;

  test("a double-slash path cannot pick the upstream host", async () => {
    const response = await rawTcp(
      `GET //127.0.0.1:${decoy.port}/hit HTTP/1.1\r\nHost: stellite.games\r\n\r\n`,
    );
    expect(response.startsWith("HTTP/1.1 400")).toBe(true);
    expect(decoyHits).toBe(0);
  });

  test("the app sees one canonical identity and no client supplied identity headers", async () => {
    appSeen.length = 0;
    await fetch(frontUrl("/page?x=1"), {
      headers: {
        "x-real-ip": "6.6.6.6",
        forwarded: "for=6.6.6.6",
        "true-client-ip": "6.6.6.6",
        "x-forwarded-for": "6.6.6.6",
        "cf-connecting-ip": "203.0.113.9",
        "x-wisp-edge-secret": "guess",
        "x-custom": "dropped",
      },
    });
    const seen = appSeen.at(-1);
    expect(seen?.url).toContain("/page?x=1");
    expect(seen?.headers.get("x-forwarded-for")).toBe("203.0.113.9");
    expect(seen?.headers.get("cf-connecting-ip")).toBe("203.0.113.9");
    for (const name of [
      "x-real-ip",
      "forwarded",
      "true-client-ip",
      "x-wisp-edge-secret",
      "x-custom",
    ]) {
      expect(seen?.headers.has(name)).toBe(false);
    }
  });

  test("compressed app responses reach the client intact", async () => {
    const response = await fetch(frontUrl("/gz"), {
      headers: { "accept-encoding": "gzip" },
    });
    expect(await response.text()).toBe("hello hello hello hello");
  });

  test("the native config carries the edge secret and keeps operator peers", () => {
    const parsed = parseToml(nativeToml) as {
      wisp_websocket: { trusted_edge_secret: string; ingress_mode: string };
      wisp: { client: { parse_real_ip_from: string[] } };
    };
    expect(parsed.wisp_websocket.ingress_mode).toBe("trusted_edge");
    expect(parsed.wisp_websocket.trusted_edge_secret).toBe(front.runtime.edgeSecret ?? "");
    expect(parsed.wisp_websocket.trusted_edge_secret).toMatch(/^[0-9a-f]{64}$/);
    expect(parsed.wisp.client.parse_real_ip_from).toEqual([
      "10.0.0.0/8",
      "127.0.0.1",
      "::1",
    ]);
  });

  test("wisp upgrades carry the secret and mirror the upstream subprotocol", async () => {
    nativeSeen.length = 0;
    const socket = new WebSocket(`ws://127.0.0.1:${front.server.port}/wisp/`, {
      protocols: ["wisp-v2", "wisp-v1"],
      headers: {
        "cf-connecting-ip": "203.0.113.9",
        "x-forwarded-for": "6.6.6.6",
        "x-real-ip": "6.6.6.6",
      },
    });
    const echoed = await new Promise<string>((resolveEcho, reject) => {
      socket.onopen = () => socket.send("ping");
      socket.onmessage = (event) => resolveEcho(String(event.data));
      socket.onerror = () => reject(new Error("socket failed"));
    });
    expect(echoed).toBe("ping");
    expect(socket.protocol).toBe("wisp-v1");
    socket.close();
    const seen = nativeSeen.at(-1);
    expect(seen?.headers.get("x-wisp-edge-secret")).toBe(front.runtime.edgeSecret ?? "");
    expect(seen?.headers.get("x-forwarded-for")).toBe("203.0.113.9");
    expect(seen?.headers.get("cf-connecting-ip")).toBe("203.0.113.9");
    expect(seen?.headers.has("x-real-ip")).toBe(false);
  });

  test("an upstream refusal reaches the client as the same status", async () => {
    const response = await rawTcp(
      [
        "GET /wisp/?reject=403 HTTP/1.1",
        "Host: stellite.games",
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "",
        "",
      ].join("\r\n"),
    );
    expect(response.startsWith("HTTP/1.1 403")).toBe(true);
  });

  test("app websockets never receive the edge secret", async () => {
    appSeen.length = 0;
    const socket = new WebSocket(`ws://127.0.0.1:${front.server.port}/ws`);
    await new Promise<void>((resolveOpen, reject) => {
      socket.onopen = () => resolveOpen();
      socket.onerror = () => reject(new Error("socket failed"));
    });
    socket.close();
    const seen = appSeen.find((entry) => entry.url.endsWith("/ws"));
    expect(seen).toBeDefined();
    expect(seen?.headers.has("x-wisp-edge-secret")).toBe(false);
  });
});
