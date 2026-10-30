// The engine as the uplink Worker runs it: the crate's wasm32 build behind
// the byte interface, driven by the runner over a scripted carrier and the
// memory frame ring. Needs the module built first:
//
//   cargo build -p wisp-ip-client --target wasm32-unknown-unknown --release
//
// (or WISP_IP_CLIENT_WASM pointing at it); skipped when it is missing.

import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { CarrierOutput } from "./carrier.js";
import {
  type EngineOutput,
  type UplinkEvent,
  WasmUplinkEngine,
  decodeOutput,
  encodeEngineConfig,
} from "./engine.js";
import { MemoryFrameRing } from "./frame-ring.js";
import { ScriptedCarrier, hex, until } from "./test-support.js";
import { UplinkRunner } from "./uplink.js";

const wasmPath =
  process.env.WISP_IP_CLIENT_WASM ??
  fileURLToPath(
    new URL("../../../target/wasm32-unknown-unknown/release/wisp_ip_client.wasm", import.meta.url),
  );
const haveWasm = existsSync(wasmPath);
if (!haveWasm) console.warn(`engine tests skipped: no ${wasmPath}`);

const HOST_MAC = Uint8Array.of(0x52, 0x54, 0x00, 0x12, 0x34, 0x56);
const GATEWAY_MAC = Uint8Array.of(0x02, 0x57, 0x49, 0x50, 0x54, 0x01);

// The relay's side, in EXTENSION.md's own bytes (section 6.1).
const SERVER_INFO = hex("05 00000000 02 00  f3 0e000000 57495054 01 01 3f00 0100 dc05 dc05");
const CONTINUE = hex("03 00000000 80000000");
const CONFIRMATION_BODY =
  "0300 0f00 01 04 18 c0a80164 ffffffff ffffffff" +
  "0400 0f00 01 04 00 00000000 c0a80101 64000000" +
  "0500 0600 dc05 dc05 0000";
const TOKEN = "11".repeat(32);
const RESUME_TOKEN = `0700 2400 1e000000 ${TOKEN}`;

function confirmation(stream: number, withToken: boolean): Uint8Array {
  const id = new Uint8Array(4);
  new DataView(id.buffer).setUint32(0, stream, true);
  const body = hex(CONFIRMATION_BODY + (withToken ? RESUME_TOKEN : ""));
  const out = new Uint8Array(5 + body.length);
  out[0] = 0xf3;
  out.set(id, 1);
  out.set(body, 5);
  return out;
}

function frame(dst: Uint8Array, type: number, payload: Uint8Array): Uint8Array {
  const f = new Uint8Array(14 + payload.length);
  f.set(dst, 0);
  f.set(HOST_MAC, 6);
  f[12] = type >> 8;
  f[13] = type & 0xff;
  f.set(payload, 14);
  return f;
}

const ARP_FOR_GATEWAY = frame(
  new Uint8Array(6).fill(0xff),
  0x0806,
  hex(`0001 0800 06 04 0001 525400123456 c0a80164 000000000000 c0a80101`),
);

// IPv4 UDP 192.168.1.100:40000 -> 93.184.216.34:443, 4 bytes.
const UDP_OUT = hex("4500 0020 0000 4000 4011 0000 c0a80164 5db8d822 9c40 01bb 000c 0000 61626364");

function events(out: EngineOutput[]): UplinkEvent[] {
  return out.flatMap((o) => (o.type === "event" ? [o.event] : []));
}

function load(): Promise<WasmUplinkEngine> {
  return WasmUplinkEngine.instantiate(readFileSync(wasmPath), {
    ipv6: false,
    hostMac: HOST_MAC,
  });
}

describe("engine byte interface", () => {
  test("the configuration input has the crate's layout", () => {
    const b = encodeEngineConfig({ ipv6: false, hostMac: HOST_MAC, openTimeoutMs: 5000 });
    expect(b.length).toBe(27);
    expect([...b.subarray(0, 4)]).toEqual([1, 0, 1, 1]);
    expect([...b.subarray(4, 10)]).toEqual([...GATEWAY_MAC]);
    expect(b[10]).toBe(1);
    expect([...b.subarray(11, 17)]).toEqual([...HOST_MAC]);
    expect(new DataView(b.buffer).getUint32(23, true)).toBe(5000);
  });

  test("outputs decode", () => {
    expect(decodeOutput(Uint8Array.of(4, 7, 0, 0, 0, 7, 0, 0, 0))).toEqual({
      type: "uni-open",
      tunnelId: 7,
      prelude: Uint8Array.of(7, 0, 0, 0),
    });
    expect(decodeOutput(Uint8Array.of(7))).toEqual({ type: "close" });
  });
});

describe.skipIf(!haveWasm)("wasm engine", () => {
  test("negotiates, opens and carries the machine's frames over WebSocket", async () => {
    const e = await load();
    e.connected("websocket", false, 0, 0);
    expect(e.drain()).toEqual([]);
    e.message("ws", SERVER_INFO, 1);
    const [info] = e.drain() as CarrierOutput[];
    // INFO 2.0 with 0xF3 "WIPT" v1, flags IPV4 | RESUME | ICMP_ECHO.
    expect(info).toEqual({
      type: "ws",
      data: hex("05 00000000 02 00 f3 07000000 57495054 01 3100"),
    });
    e.message("ws", CONTINUE, 2);
    expect(e.drain()).toEqual([{ type: "ws", data: hex("f3 01000000 0100 0200 0100") }]);

    e.message("ws", confirmation(1, false), 3);
    const [up] = events(e.drain());
    if (up?.type !== "link-up") throw new Error(`expected link-up, got ${JSON.stringify(up)}`);
    expect(up.resumed).toBe(false);
    expect(up.flowsLost).toBe(false);
    expect(up.config.addresses).toEqual([
      { address: "192.168.1.100", prefix: 24, valid: 4294967295, preferred: 4294967295 },
    ]);
    expect(up.config.routes).toEqual([
      { dest: "0.0.0.0", prefix: 0, gateway: "192.168.1.1", metric: 100 },
    ]);
    expect(up.config.mtu).toBe(1500);

    // The router answers ARP for the gateway on the wire.
    e.wireFrame(ARP_FOR_GATEWAY, 4);
    const [arp] = e.drain();
    if (arp?.type !== "wire") throw new Error("expected an ARP reply");
    expect([...arp.frame.subarray(0, 6)]).toEqual([...HOST_MAC]);
    expect([...arp.frame.subarray(6, 12)]).toEqual([...GATEWAY_MAC]);
    expect(arp.frame[21]).toBe(2);

    // An IP packet for the gateway becomes one DATA on stream 1.
    e.wireFrame(frame(GATEWAY_MAC, 0x0800, UDP_OUT), 5);
    const [data] = e.drain() as CarrierOutput[];
    if (data?.type !== "ws") throw new Error("expected DATA");
    expect([...data.data.subarray(0, 5)]).toEqual([0x02, 1, 0, 0, 0]);
    expect([...data.data.subarray(5)]).toEqual([...UDP_OUT]);
    expect(e.timeout()).toBeNull();
  });

  test("on WebTransport the engine speaks first on the control bidi", async () => {
    const e = await load();
    e.connected("webtransport", true, 1024, 0);
    const [info] = e.drain();
    if (info?.type !== "control") throw new Error("expected control bytes");
    // [bodyLen][INFO][0xF3][7]["WIPT"][1][flags incl. DATAGRAMS | FRAGMENTS]
    expect(info.data[4]).toBe(0x01);
    expect(info.data[5]).toBe(0xf3);
    expect(info.data[15] & 0x0c).toBe(0x0c);
  });

  test("the runner reconnects and resumes the tunnel", async () => {
    const engine = await load();
    const [uplinkEnd, wireEnd] = MemoryFrameRing.pair();
    const carriers = [new ScriptedCarrier("websocket"), new ScriptedCarrier("websocket")];
    const seen: UplinkEvent[] = [];
    const runner = new UplinkRunner({
      engine,
      ring: uplinkEnd,
      connect: async () => carriers.shift() as ScriptedCarrier,
      onEvent: (ev) => seen.push(ev),
      reconnectDelayMs: 5,
    });
    const [first, second] = carriers;
    const wireOut: Uint8Array[] = [];
    wireEnd.onFrame((f) => wireOut.push(f));
    runner.start();
    await until(() => first.sink !== null);
    first.receive(SERVER_INFO);
    first.receive(CONTINUE);
    first.receive(confirmation(1, true));
    await until(() => seen.some((ev) => ev.type === "link-up"));

    // The netkernel's ARP request and a packet, through the ring.
    wireEnd.push(ARP_FOR_GATEWAY);
    wireEnd.push(frame(GATEWAY_MAC, 0x0800, UDP_OUT));
    await until(() => wireOut.length === 1 && first.sent.length === 3);
    const data = first.sent[2];
    expect(data.type === "ws" && data.data[0]).toBe(0x02);

    // The carrier drops; the runner reconnects and the engine resumes.
    first.close("network changed");
    await until(() => second.sink !== null);
    expect(seen.find((ev) => ev.type === "detached")).toBeDefined();
    second.receive(SERVER_INFO);
    second.receive(CONTINUE);
    const open = second.sent[1];
    if (open?.type !== "ws") throw new Error("expected the OPEN");
    // OPEN, then RESUME with the token from the first confirmation.
    expect([...open.data]).toEqual([...hex(`f3 01000000 0100 0200 0100 0800 2000 ${TOKEN}`)]);
    second.receive(confirmation(1, true));
    await until(() => seen.filter((ev) => ev.type === "link-up").length === 2);
    const resumed = seen.filter((ev) => ev.type === "link-up")[1];
    expect(resumed.type === "link-up" && resumed.resumed).toBe(true);

    runner.stop();
    expect(second.closedWith).not.toBeNull();
    const last = second.sent.at(-1);
    expect(last?.type === "ws" && last.data[0]).toBe(0x04); // CLOSE for the tunnel
  });
});
