// The WebSocket carriage (Wisp v2, EXTENSION.md section 6.1), for networks
// that block UDP to the relay. One binary message per Wisp packet.

import type { Carrier, CarrierOutput, CarrierSink, CarrierStats } from "./carrier.js";
import { CarrierUnavailable } from "./carrier.js";
import { type WebSocketConstructor, type WebSocketLike, WS_OPEN } from "./web.js";

/** wisp-rust's `Auto` mode speaks Wisp v2, which has extensions, only to a
 *  client that offers this subprotocol. */
export const WISP_V2_PROTOCOL = "wisp-v2";

/** Wisp DATA: the packet type of an IP packet on a tunnel. */
const WISP_DATA = 0x02;

export interface WebSocketCarrierOptions {
  /** The constructor; the global `WebSocket` by default. */
  WebSocket?: WebSocketConstructor;
  timeoutMs?: number;
  /**
   * Bytes the socket may hold unsent before IP packets are dropped instead
   * of queued. Control packets are always sent.
   */
  highWaterBytes?: number;
}

export class WebSocketCarrier implements Carrier {
  readonly kind = "websocket" as const;
  readonly datagrams = false;
  readonly maxDatagramSize = 0;
  readonly stats: CarrierStats = { sent: 0, received: 0, dropped: 0 };
  private sink: CarrierSink | null = null;
  private pending: Uint8Array[] = [];
  private ended: string | null = null;
  private readonly highWater: number;

  /** Opens `url` offering `wisp-v2`. */
  static connect(url: string, options: WebSocketCarrierOptions = {}): Promise<WebSocketCarrier> {
    const WS =
      options.WebSocket ?? (globalThis as { WebSocket?: WebSocketConstructor }).WebSocket;
    if (!WS) return Promise.reject(new CarrierUnavailable("WebSocket is not available here"));
    const ws = new WS(url, [WISP_V2_PROTOCOL]);
    ws.binaryType = "arraybuffer";
    // Listeners go on at once so no early message is lost.
    const carrier = new WebSocketCarrier(ws, options.highWaterBytes ?? 4 << 20);
    const timeoutMs = options.timeoutMs ?? 10_000;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        ws.close();
        reject(new Error(`WebSocket open timed out after ${timeoutMs} ms`));
      }, timeoutMs);
      ws.addEventListener("open", () => {
        clearTimeout(timer);
        resolve(carrier);
      });
      ws.addEventListener("error", () => {
        clearTimeout(timer);
        reject(new Error("WebSocket failed to open"));
      });
      ws.addEventListener("close", (ev) => {
        clearTimeout(timer);
        reject(new Error(`WebSocket closed before it opened (${ev.code ?? 0})`));
      });
    });
  }

  private constructor(
    private readonly ws: WebSocketLike,
    highWater: number,
  ) {
    this.highWater = highWater;
    ws.addEventListener("message", (ev) => {
      const data = ev.data;
      if (!(data instanceof ArrayBuffer)) return; // Wisp is binary only
      this.stats.received++;
      const bytes = new Uint8Array(data);
      if (this.sink) this.sink.message("ws", bytes);
      else this.pending.push(bytes);
    });
    ws.addEventListener("close", (ev) => this.end(`closed (${ev.code ?? 0} ${ev.reason ?? ""})`));
    ws.addEventListener("error", () => this.end("socket error"));
  }

  /** The subprotocol the server chose: `wisp-v2`, or "" for Wisp v1. */
  get protocol(): string {
    return this.ws.protocol;
  }

  attach(sink: CarrierSink): void {
    this.sink = sink;
    const queued = this.pending;
    this.pending = [];
    for (const m of queued) sink.message("ws", m);
    if (this.ended !== null) sink.closed(this.ended);
  }

  private end(reason: string): void {
    if (this.ended !== null) return;
    this.ended = reason;
    this.sink?.closed(reason);
  }

  send(out: CarrierOutput): void {
    switch (out.type) {
      case "ws":
        if (this.ws.readyState !== WS_OPEN) {
          this.stats.dropped++;
          return;
        }
        if (out.data[0] === WISP_DATA && this.ws.bufferedAmount > this.highWater) {
          this.stats.dropped++;
          return;
        }
        this.stats.sent++;
        this.ws.send(out.data);
        return;
      case "close":
        this.close("closed by the uplink");
        return;
      default:
        throw new Error(`${out.type} on a WebSocket carrier`);
    }
  }

  close(reason = "closed"): void {
    if (this.ended === null) {
      try {
        this.ws.close(1000, reason.slice(0, 120));
      } catch {
        // already closing
      }
    }
    this.end(reason);
  }
}
