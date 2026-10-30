// The browser's path against a real relay: the engine's wasm build, the
// WebSocket carriage, happy eyeballs and the runner, with a userspace
// packet generator on the frame ring standing in for the netkernel. Runs
// only when WISP_RELAY_URL names a wispd with IP tunnels whose stand-in
// internet answers UDP and ICMP echo at 192.88.99.2 (the wisp-ip-client
// crate's `vm_e2e` test `serve_a_relay_for_an_outside_client` brings one
// up in the Linux VM; Lima forwards its port to this host).

import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { type UplinkEvent, WasmUplinkEngine } from "./engine.js";
import { MemoryFrameRing } from "./frame-ring.js";
import { happyEyeballs } from "./happy-eyeballs.js";
import { until } from "./test-support.js";
import { UplinkRunner } from "./uplink.js";
import { WebSocketCarrier } from "./websocket.js";

const url = process.env.WISP_RELAY_URL;
const wasmPath =
  process.env.WISP_IP_CLIENT_WASM ??
  fileURLToPath(
    new URL("../../../target/wasm32-unknown-unknown/release/wisp_ip_client.wasm", import.meta.url),
  );
const run = url !== undefined && existsSync(wasmPath);

const HOST_MAC = [0x52, 0x54, 0x00, 0x4c, 0x53, 0x37];
const GATEWAY_MAC = [0x02, 0x57, 0x49, 0x50, 0x54, 0x01];
const CLIENT = [192, 168, 1, 100];
const GATEWAY = [192, 168, 1, 1];
const SERVER = [192, 88, 99, 2];

function checksum(b: Uint8Array): number {
  let sum = 0;
  for (let i = 0; i + 1 < b.length; i += 2) sum += (b[i] << 8) | b[i + 1];
  if (b.length % 2) sum += b[b.length - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return ~sum & 0xffff;
}

function ipv4(protocol: number, payload: Uint8Array): Uint8Array {
  const p = new Uint8Array(20 + payload.length);
  p.set([0x45, 0, (p.length >> 8) & 0xff, p.length & 0xff, 0, 1, 0x40, 0, 64, protocol, 0, 0]);
  p.set(CLIENT, 12);
  p.set(SERVER, 16);
  const c = checksum(p.subarray(0, 20));
  p[10] = c >> 8;
  p[11] = c & 0xff;
  p.set(payload, 20);
  return p;
}

function udp(data: Uint8Array): Uint8Array {
  const u = new Uint8Array(8 + data.length);
  u.set([0x9c, 0x40, 0, 7, (u.length >> 8) & 0xff, u.length & 0xff, 0, 0]); // checksum 0: none (IPv4)
  u.set(data, 8);
  return ipv4(17, u);
}

function echoRequest(id: number, seq: number): Uint8Array {
  const m = new Uint8Array(16);
  m.set([8, 0, 0, 0, id >> 8, id & 0xff, seq >> 8, seq & 0xff]);
  m.set(new TextEncoder().encode("wisp-ip!"), 8);
  const c = checksum(m);
  m[2] = c >> 8;
  m[3] = c & 0xff;
  return ipv4(1, m);
}

function frame(dst: number[], type: number, payload: Uint8Array): Uint8Array {
  const f = new Uint8Array(14 + payload.length);
  f.set(dst, 0);
  f.set(HOST_MAC, 6);
  f[12] = type >> 8;
  f[13] = type & 0xff;
  f.set(payload, 14);
  return f;
}

const arpRequest = () => {
  const a = new Uint8Array(28);
  a.set([0, 1, 8, 0, 6, 4, 0, 1]);
  a.set(HOST_MAC, 8);
  a.set(CLIENT, 14);
  a.set(GATEWAY, 24);
  return frame([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0x0806, a);
};

describe.skipIf(!run)("against a real relay", () => {
  test("ARP, UDP echo and ICMP echo through IP_TUNNEL over WebSocket", async () => {
    const engine = await WasmUplinkEngine.instantiate(readFileSync(wasmPath), {
      ipv6: false,
      hostMac: Uint8Array.from(HOST_MAC),
    });
    const [uplinkEnd, wire] = MemoryFrameRing.pair();
    const events: UplinkEvent[] = [];
    const runner = new UplinkRunner({
      engine,
      ring: uplinkEnd,
      // Node and bun have no WebTransport: WebSocket only.
      connect: () => happyEyeballs({ webSocket: () => WebSocketCarrier.connect(url as string) }),
      onEvent: (e) => events.push(e),
    });
    const frames: Uint8Array[] = [];
    wire.onFrame((f) => frames.push(f));
    runner.start();
    await until(() => events.some((e) => e.type === "link-up"), 15_000);
    const up = events.find((e) => e.type === "link-up");
    expect(up?.type === "link-up" && up.config.addresses[0].address).toBe("192.168.1.100");
    expect(runner.connectedCarrier?.kind).toBe("websocket");

    wire.push(arpRequest());
    await until(() => frames.length === 1);
    expect(frames[0][21]).toBe(2); // ARP reply, from the router

    const hello = new TextEncoder().encode("hello from bun through wispd");
    wire.push(frame(GATEWAY_MAC, 0x0800, udp(hello)));
    await until(() => frames.length === 2, 10_000);
    const ip = frames[1].subarray(14);
    expect([...frames[1].subarray(0, 6)]).toEqual(HOST_MAC);
    expect(ip[9]).toBe(17);
    expect([...ip.subarray(12, 16)]).toEqual(SERVER);
    expect(ip[8]).toBe(62); // TTL through two routers
    expect(new TextDecoder().decode(ip.subarray(28, 28 + hello.length))).toBe(
      "hello from bun through wispd",
    );

    wire.push(frame(GATEWAY_MAC, 0x0800, echoRequest(0x4c36, 1)));
    await until(() => frames.length === 3, 10_000);
    const reply = frames[2].subarray(14);
    expect(reply[9]).toBe(1);
    expect(reply[20]).toBe(0); // echo reply
    expect((reply[24] << 8) | reply[25]).toBe(0x4c36);

    runner.stop();
    expect(events.some((e) => e.type === "link-down")).toBe(true);
  }, 30_000);
});
