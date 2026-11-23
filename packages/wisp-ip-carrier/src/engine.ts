// The uplink engine: the `wisp-ip-client` crate built for
// wasm32-unknown-unknown (its `src/abi.rs` documents the exports and the
// byte layouts used here). The engine owns the protocol, the virtual router
// and resume; the carriers and the frame ring only move bytes.

import type { CarrierKind, CarrierOutput } from "./carrier.js";

export interface AddressConfig {
  address: string;
  prefix: number;
  valid: number;
  preferred: number;
}

export interface RouteConfig {
  dest: string;
  prefix: number;
  gateway: string;
  metric: number;
}

/** What the relay's open confirmation configures on the machine's link. */
export interface LinkConfig {
  addresses: AddressConfig[];
  routes: RouteConfig[];
  mtu: number;
  maxPacket: number;
  maxDatagramPayload: number;
  dns: { servers: string[]; search: string; resolvConf: string } | null;
}

export type UplinkEvent =
  | { type: "unsupported"; why: string }
  | { type: "link-up"; resumed: boolean; flowsLost: boolean; config: LinkConfig }
  | { type: "link-changed"; config: LinkConfig }
  | { type: "detached"; resumeUntilMs: number }
  | { type: "open-timed-out" }
  | { type: "link-down"; reason: string; close: number; error: number; message: string }
  | { type: "connection-failed"; why: string };

export type EngineOutput =
  | CarrierOutput
  | { type: "wire"; frame: Uint8Array }
  | { type: "event"; event: UplinkEvent };

/** The engine as the uplink runner drives it. Times are milliseconds. */
export interface UplinkEngine {
  connected(kind: CarrierKind, datagrams: boolean, maxDatagramSize: number, now: number): void;
  disconnected(now: number): void;
  message(channel: "ws" | "control" | "datagram", data: Uint8Array, now: number): void;
  uni(stream: number, data: Uint8Array, now: number): void;
  uniEnd(stream: number): void;
  maxDatagramSize(size: number): void;
  wireFrame(frame: Uint8Array, now: number): void;
  timer(now: number): void;
  close(now: number): void;
  /** Everything the engine produced since the last call, in order. */
  drain(): EngineOutput[];
  /** When `timer` has work next, or null. */
  timeout(): number | null;
}

export interface EngineConfig {
  ipv4?: boolean;
  ipv6?: boolean;
  resume?: boolean;
  icmpEcho?: boolean;
  /** The gateway's Ethernet address on the machine's link. */
  gatewayMac?: Uint8Array;
  /** `eth0`'s address, when the machine config fixes it. */
  hostMac?: Uint8Array;
  routerLifetimeS?: number;
  raIntervalMs?: number;
  openTimeoutMs?: number;
}

export interface WasmEngineExports {
  memory: WebAssembly.Memory;
  wipc_reset(): number;
  wipc_input(len: number): number;
  wipc_push(kind: number, len: number, now: number): number;
  wipc_next(): number;
  wipc_output(): number;
  wipc_timeout(): number;
}

const IN = {
  CONFIGURE: 1,
  CONNECTED: 2,
  DISCONNECTED: 3,
  WS_MESSAGE: 4,
  WT_CONTROL: 5,
  WT_DATAGRAM: 6,
  WT_UNI: 7,
  WT_UNI_END: 8,
  WIRE_FRAME: 9,
  MAX_DATAGRAM: 10,
  TIMER: 11,
  CLOSE: 12,
} as const;

const OUT = {
  WS_SEND: 1,
  WT_CONTROL: 2,
  WT_DATAGRAM: 3,
  WT_UNI_OPEN: 4,
  WT_UNI_CHUNK: 5,
  WT_UNI_FINISH: 6,
  CLOSE: 7,
  WIRE: 8,
  EVENT: 9,
} as const;

const EV = {
  UNSUPPORTED: 1,
  LINK_UP: 2,
  LINK_CHANGED: 3,
  DETACHED: 4,
  OPEN_TIMED_OUT: 5,
  LINK_DOWN: 6,
  CONNECTION_FAILED: 7,
} as const;

/** The 27-byte configuration input of `src/abi.rs`. */
export function encodeEngineConfig(c: EngineConfig): Uint8Array {
  const b = new Uint8Array(27);
  const v = new DataView(b.buffer);
  b[0] = c.ipv4 === false ? 0 : 1;
  b[1] = c.ipv6 === false ? 0 : 1;
  b[2] = c.resume === false ? 0 : 1;
  b[3] = c.icmpEcho === false ? 0 : 1;
  b.set(c.gatewayMac ?? Uint8Array.of(0x02, 0x57, 0x49, 0x50, 0x54, 0x01), 4);
  if (c.hostMac) {
    b[10] = 1;
    b.set(c.hostMac, 11);
  }
  v.setUint16(17, c.routerLifetimeS ?? 1800, true);
  v.setUint32(19, c.raIntervalMs ?? 200_000, true);
  v.setUint32(23, c.openTimeoutMs ?? 15_000, true);
  return b;
}

const text = new TextDecoder();

function u32(b: Uint8Array, at: number): number {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(at, true);
}

export function decodeEvent(b: Uint8Array): UplinkEvent {
  const json = (from: number) => JSON.parse(text.decode(b.subarray(from)));
  switch (b[0]) {
    case EV.UNSUPPORTED:
      return { type: "unsupported", why: json(1).why };
    case EV.LINK_UP:
      return { type: "link-up", resumed: b[1] === 1, flowsLost: b[2] === 1, config: json(3) };
    case EV.LINK_CHANGED:
      return { type: "link-changed", config: json(1) };
    case EV.DETACHED:
      return {
        type: "detached",
        resumeUntilMs: new DataView(b.buffer, b.byteOffset + 1, 8).getFloat64(0, true),
      };
    case EV.OPEN_TIMED_OUT:
      return { type: "open-timed-out" };
    case EV.LINK_DOWN: {
      const d = json(1);
      return { type: "link-down", reason: d.reason, close: d.close, error: d.error, message: d.message };
    }
    case EV.CONNECTION_FAILED:
      return { type: "connection-failed", why: json(1).why };
    default:
      throw new Error(`unknown engine event ${b[0]}`);
  }
}

export function decodeOutput(b: Uint8Array): EngineOutput {
  const body = b.subarray(1);
  switch (b[0]) {
    case OUT.WS_SEND:
      return { type: "ws", data: body };
    case OUT.WT_CONTROL:
      return { type: "control", data: body };
    case OUT.WT_DATAGRAM:
      return { type: "datagram", data: body };
    case OUT.WT_UNI_OPEN:
      return { type: "uni-open", tunnelId: u32(body, 0), prelude: body.subarray(4) };
    case OUT.WT_UNI_CHUNK:
      return { type: "uni-chunk", tunnelId: u32(body, 0), data: body.subarray(4) };
    case OUT.WT_UNI_FINISH:
      return { type: "uni-finish", tunnelId: u32(body, 0) };
    case OUT.CLOSE:
      return { type: "close" };
    case OUT.WIRE:
      return { type: "wire", frame: body };
    case OUT.EVENT:
      return { type: "event", event: decodeEvent(body) };
    default:
      throw new Error(`unknown engine output ${b[0]}`);
  }
}

/** The engine as a WebAssembly instance (one engine per instance). */
export class WasmUplinkEngine implements UplinkEngine {
  private constructor(private readonly x: WasmEngineExports) {}

  /** Instantiates `module` (the crate's `wisp_ip_client.wasm`) and applies `config`. */
  static async instantiate(
    module: WebAssembly.Module | ArrayBuffer | ArrayBufferView,
    config: EngineConfig = {},
  ): Promise<WasmUplinkEngine> {
    const compiled =
      module instanceof WebAssembly.Module ? module : await WebAssembly.compile(module as unknown as ArrayBuffer);
    const instance = await WebAssembly.instantiate(compiled, {});
    const engine = new WasmUplinkEngine(instance.exports as unknown as WasmEngineExports);
    engine.push(IN.CONFIGURE, encodeEngineConfig(config), 0);
    return engine;
  }

  private push(kind: number, data: Uint8Array, now: number): void {
    const ptr = this.x.wipc_input(data.byteLength);
    // The memory may have grown: views are taken after every call.
    new Uint8Array(this.x.memory.buffer, ptr, data.byteLength).set(data);
    const status = this.x.wipc_push(kind, data.byteLength, now);
    if (status !== 0) throw new Error(`engine input ${kind} refused (${status})`);
  }

  private static readonly empty = new Uint8Array(0);

  connected(kind: CarrierKind, datagrams: boolean, maxDatagramSize: number, now: number): void {
    const b = new Uint8Array(6);
    b[0] = kind === "websocket" ? 1 : 2;
    b[1] = datagrams ? 1 : 0;
    new DataView(b.buffer).setUint32(2, maxDatagramSize >>> 0, true);
    this.push(IN.CONNECTED, b, now);
  }

  disconnected(now: number): void {
    this.push(IN.DISCONNECTED, WasmUplinkEngine.empty, now);
  }

  message(channel: "ws" | "control" | "datagram", data: Uint8Array, now: number): void {
    const kind =
      channel === "ws" ? IN.WS_MESSAGE : channel === "control" ? IN.WT_CONTROL : IN.WT_DATAGRAM;
    this.push(kind, data, now);
  }

  uni(stream: number, data: Uint8Array, now: number): void {
    const b = new Uint8Array(4 + data.byteLength);
    new DataView(b.buffer).setUint32(0, stream >>> 0, true);
    b.set(data, 4);
    this.push(IN.WT_UNI, b, now);
  }

  uniEnd(stream: number): void {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, stream >>> 0, true);
    this.push(IN.WT_UNI_END, b, 0);
  }

  maxDatagramSize(size: number): void {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, size >>> 0, true);
    this.push(IN.MAX_DATAGRAM, b, 0);
  }

  wireFrame(frame: Uint8Array, now: number): void {
    this.push(IN.WIRE_FRAME, frame, now);
  }

  timer(now: number): void {
    this.push(IN.TIMER, WasmUplinkEngine.empty, now);
  }

  close(now: number): void {
    this.push(IN.CLOSE, WasmUplinkEngine.empty, now);
  }

  drain(): EngineOutput[] {
    const out: EngineOutput[] = [];
    for (;;) {
      const len = this.x.wipc_next();
      if (len === 0) return out;
      const ptr = this.x.wipc_output();
      // Copied out: the next call reuses the buffer.
      out.push(decodeOutput(new Uint8Array(this.x.memory.buffer, ptr, len).slice()));
    }
  }

  timeout(): number | null {
    const t = this.x.wipc_timeout();
    return t < 0 ? null : t;
  }
}
