import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import type { CarrierSink } from "./carrier.js";
import { until } from "./test-support.js";
import type { WebSocketConstructor } from "./web.js";
import { WISP_V2_PROTOCOL, WebSocketCarrier } from "./websocket.js";

// A stand-in relay: it takes the wisp-v2 subprotocol, greets with two
// messages before the client says anything, and echoes binary messages.
let server: ReturnType<typeof Bun.serve>;
const offered: string[] = [];

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    fetch(req, srv) {
      const proto = req.headers.get("sec-websocket-protocol") ?? "";
      offered.push(proto);
      const take = proto.split(",").map((p) => p.trim()).includes(WISP_V2_PROTOCOL);
      const headers: Record<string, string> = take
        ? { "Sec-WebSocket-Protocol": WISP_V2_PROTOCOL }
        : {};
      if (srv.upgrade(req, { headers, data: undefined })) {
        return undefined;
      }
      return new Response("no", { status: 400 });
    },
    websocket: {
      open(ws) {
        ws.sendBinary(Uint8Array.of(0x05, 0, 0, 0, 0, 2, 0));
        ws.sendBinary(Uint8Array.of(0x03, 0, 0, 0, 0, 128, 0, 0, 0));
      },
      message(ws, msg) {
        if (typeof msg === "string") return;
        if (msg[0] === 0xff) {
          ws.close(1000, "bye");
          return;
        }
        ws.sendBinary(msg);
      },
    },
  });
});

afterAll(() => {
  server.stop(true);
});

function url(): string {
  return `ws://127.0.0.1:${server.port}/`;
}

function recorder() {
  const got = { ws: [] as Uint8Array[], closed: [] as string[] };
  const sink: CarrierSink = {
    message: (ch, d) => {
      if (ch === "ws") got.ws.push(d);
    },
    uni: () => {},
    uniEnd: () => {},
    maxDatagramSize: () => {},
    closed: (r) => got.closed.push(r),
  };
  return { got, sink };
}

describe("WebSocket carriage", () => {
  test("offers wisp-v2 and keeps what arrives before the attach", async () => {
    const c = await WebSocketCarrier.connect(url());
    expect(offered.at(-1)).toContain(WISP_V2_PROTOCOL);
    expect(c.protocol).toBe(WISP_V2_PROTOCOL);
    expect(c.datagrams).toBe(false);
    expect(c.maxDatagramSize).toBe(0);
    await new Promise((r) => setTimeout(r, 30));
    const { got, sink } = recorder();
    c.attach(sink);
    expect(got.ws.map((m) => m[0])).toEqual([0x05, 0x03]);
    // One message per Wisp packet, both ways.
    const data = Uint8Array.of(0x02, 7, 0, 0, 0, 0x45, 0, 0, 20);
    c.send({ type: "ws", data });
    await until(() => got.ws.length === 3);
    expect([...got.ws[2]]).toEqual([...data]);
    c.close();
    expect(got.closed.length).toBe(1);
  });

  test("reports the relay's close", async () => {
    const c = await WebSocketCarrier.connect(url());
    const { got, sink } = recorder();
    c.attach(sink);
    c.send({ type: "ws", data: Uint8Array.of(0xff) });
    await until(() => got.closed.length === 1);
    expect(got.closed[0]).toContain("1000");
  });

  test("fails to connect to nothing", async () => {
    await expect(WebSocketCarrier.connect("ws://127.0.0.1:1/", { timeoutMs: 2000 })).rejects.toThrow();
  });

  test("drops IP packets, never control, above the high-water mark", () => {
    const sent: Uint8Array[] = [];
    // biome-ignore lint: a loose stand-in for the browser's socket
    let listeners: Record<string, ((ev: any) => void)[]> = {};
    class Busy {
      binaryType = "";
      readyState = 1;
      bufferedAmount = 10_000_000;
      protocol = WISP_V2_PROTOCOL;
      constructor() {
        listeners = {};
        queueMicrotask(() => {
          for (const l of listeners.open ?? []) l(undefined);
        });
      }
      send(d: Uint8Array) {
        sent.push(d);
      }
      close() {}
      // biome-ignore lint: as above
      addEventListener(t: string, l: (ev: any) => void) {
        (listeners[t] ??= []).push(l);
      }
    }
    return WebSocketCarrier.connect("ws://x/", {
      WebSocket: Busy as unknown as WebSocketConstructor,
    }).then((c) => {
      c.send({ type: "ws", data: Uint8Array.of(0x02, 1, 0, 0, 0, 0x45) });
      c.send({ type: "ws", data: Uint8Array.of(0xf3, 1, 0, 0, 0, 1, 0, 2, 0, 1, 0) });
      expect(sent.map((d) => d[0])).toEqual([0xf3]);
      expect(c.stats.dropped).toBe(1);
    });
  });
});
