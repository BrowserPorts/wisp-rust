// The uplink Worker's loop: one engine, one frame ring, and whichever
// carrier connects. It reconnects when the carrier drops; the engine
// decides whether the new connection resumes the tunnel (decision LD13).

import type { Carrier, CarrierSink } from "./carrier.js";
import type { EngineOutput, UplinkEngine, UplinkEvent } from "./engine.js";
import type { FrameRing } from "./frame-ring.js";

export interface UplinkOptions {
  engine: UplinkEngine;
  ring: FrameRing;
  /** Connects a carrier, for example `() => happyEyeballs({...})`. */
  connect: () => Promise<Carrier>;
  onEvent?: (event: UplinkEvent) => void;
  /** Monotonic milliseconds; `performance.now` by default. */
  now?: () => number;
  /** First reconnect delay, doubled after each failure up to `maxDelayMs`. */
  reconnectDelayMs?: number;
  maxReconnectDelayMs?: number;
}

export class UplinkRunner {
  private carrier: Carrier | null = null;
  private stopped = true;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private timerAt: number | null = null;
  private retry: ReturnType<typeof setTimeout> | null = null;
  private delay: number;
  private readonly now: () => number;
  private generation = 0;

  constructor(private readonly o: UplinkOptions) {
    this.now = o.now ?? (() => performance.now());
    this.delay = o.reconnectDelayMs ?? 250;
  }

  get connectedCarrier(): Carrier | null {
    return this.carrier;
  }

  start(): void {
    if (!this.stopped) return;
    this.stopped = false;
    this.o.ring.onFrame((frame) => {
      this.o.engine.wireFrame(frame, this.now());
      this.flush();
    });
    void this.connect();
  }

  /** Closes the tunnel and the carrier; no reconnect follows. */
  stop(): void {
    if (this.stopped) return;
    this.stopped = true;
    this.o.ring.onFrame(null);
    if (this.retry) clearTimeout(this.retry);
    this.retry = null;
    this.o.engine.close(this.now());
    this.flush();
    this.carrier?.close("uplink stopped");
    this.carrier = null;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  private async connect(): Promise<void> {
    const generation = ++this.generation;
    let carrier: Carrier;
    try {
      carrier = await this.o.connect();
    } catch {
      this.scheduleReconnect();
      return;
    }
    if (this.stopped || generation !== this.generation) {
      carrier.close("uplink stopped");
      return;
    }
    this.carrier = carrier;
    const engine = this.o.engine;
    const sink: CarrierSink = {
      message: (channel, data) => {
        if (this.carrier !== carrier) return;
        engine.message(channel, data, this.now());
        this.flush();
      },
      uni: (stream, data) => {
        if (this.carrier !== carrier) return;
        engine.uni(stream, data, this.now());
        this.flush();
      },
      uniEnd: (stream) => {
        if (this.carrier === carrier) engine.uniEnd(stream);
      },
      maxDatagramSize: (size) => {
        if (this.carrier === carrier) engine.maxDatagramSize(size);
      },
      closed: () => {
        if (this.carrier !== carrier) return;
        this.carrier = null;
        engine.disconnected(this.now());
        this.flush();
        this.scheduleReconnect();
      },
    };
    carrier.attach(sink);
    if (this.carrier !== carrier) return; // closed before attach
    engine.connected(carrier.kind, carrier.datagrams, carrier.maxDatagramSize, this.now());
    this.flush();
  }

  private scheduleReconnect(): void {
    if (this.stopped || this.retry) return;
    const delay = this.delay;
    this.delay = Math.min(this.delay * 2, this.o.maxReconnectDelayMs ?? 8_000);
    this.retry = setTimeout(() => {
      this.retry = null;
      void this.connect();
    }, delay);
  }

  private handle(out: EngineOutput): void {
    switch (out.type) {
      case "wire":
        this.o.ring.push(out.frame);
        return;
      case "event":
        if (out.event.type === "link-up") this.delay = this.o.reconnectDelayMs ?? 250;
        if (out.event.type === "unsupported") {
          // The relay has no IP_TUNNEL: reconnecting will not change that
          // (decision LD4).
          this.stopped = true;
        }
        this.o.onEvent?.(out.event);
        return;
      case "close":
        this.carrier?.close("closed by the engine");
        return;
      default:
        this.carrier?.send(out);
    }
  }

  private flush(): void {
    for (const out of this.o.engine.drain()) this.handle(out);
    this.armTimer();
  }

  private armTimer(): void {
    const at = this.o.engine.timeout();
    if (at === this.timerAt) return;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    this.timerAt = at;
    if (at === null || this.stopped) return;
    this.timer = setTimeout(
      () => {
        this.timer = null;
        this.timerAt = null;
        this.o.engine.timer(this.now());
        this.flush();
      },
      Math.max(0, at - this.now()),
    );
  }
}
