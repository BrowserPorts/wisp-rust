// The WebTransport carriage (wisp-wt, EXTENSION.md section 6.2): the control
// bidi, IP datagrams of kind 0x02, and one uni stream per tunnel and
// direction when the session or the relay has no datagrams.

import {
  type Carrier,
  type CarrierOutput,
  type CarrierSink,
  type CarrierStats,
  CarrierUnavailable,
} from "./carrier.js";
import {
  type WebTransportBidiLike,
  type WebTransportConstructor,
  type WebTransportHash,
  type WebTransportLike,
  readAll,
  readEach,
  withTimeout,
} from "./web.js";

export interface WebTransportCarrierOptions {
  /** The constructor; the global `WebTransport` by default. */
  WebTransport?: WebTransportConstructor;
  /** For a relay with a self-signed certificate (development). */
  serverCertificateHashes?: WebTransportHash[];
  /** How long to wait for the session and the control bidi. */
  timeoutMs?: number;
  /** Datagrams, and packets of each outgoing uni stream, that may wait. */
  maxQueuedChunks?: number;
}

interface UniOut {
  writer: Promise<WritableStreamDefaultWriter<Uint8Array> | null>;
  chain: Promise<void>;
  queued: number;
}

type Pending =
  | { kind: "control" | "datagram"; data: Uint8Array }
  | { kind: "uni"; stream: number; data: Uint8Array }
  | { kind: "uni-end"; stream: number };

export class WebTransportCarrier implements Carrier {
  readonly kind = "webtransport" as const;
  readonly stats: CarrierStats = { sent: 0, received: 0, dropped: 0 };
  private sink: CarrierSink | null = null;
  private pending: Pending[] = [];
  private readonly control: WritableStreamDefaultWriter<Uint8Array>;
  private readonly datagramWriter: WritableStreamDefaultWriter<Uint8Array> | null;
  private readonly uniOut = new Map<number, UniOut>();
  private lastMax: number;
  private nextStream = 1;
  private datagramsInFlight = 0;
  private ended = false;
  private readonly maxQueued: number;

  /** Opens a session to `url` and its control bidi. */
  static async connect(
    url: string,
    options: WebTransportCarrierOptions = {},
  ): Promise<WebTransportCarrier> {
    const WT =
      options.WebTransport ??
      (globalThis as { WebTransport?: WebTransportConstructor }).WebTransport;
    if (!WT) throw new CarrierUnavailable("WebTransport is not available here");
    const timeout = options.timeoutMs ?? 10_000;
    const wt = new WT(
      url,
      options.serverCertificateHashes
        ? { serverCertificateHashes: options.serverCertificateHashes }
        : undefined,
    );
    try {
      await withTimeout(wt.ready, timeout, "WebTransport session");
      // The relay takes the session's first bidi as the control bidi.
      const control = await withTimeout(
        wt.createBidirectionalStream(),
        timeout,
        "control bidi",
      );
      return new WebTransportCarrier(wt, control, options.maxQueuedChunks ?? 256);
    } catch (e) {
      try {
        wt.close({ closeCode: 0, reason: "connect failed" });
      } catch {
        // already closed
      }
      throw e;
    }
  }

  private constructor(
    private readonly wt: WebTransportLike,
    controlBidi: WebTransportBidiLike,
    maxQueued: number,
  ) {
    this.maxQueued = maxQueued;
    this.control = controlBidi.writable.getWriter();
    let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
    try {
      writer = wt.datagrams.writable.getWriter();
    } catch {
      writer = null;
    }
    this.datagramWriter = writer;
    this.lastMax = writer ? wt.datagrams.maxDatagramSize : 0;
    this.readLoops(controlBidi);
    wt.closed.then(
      () => this.end("session closed"),
      (e: unknown) => this.end(`session failed: ${String(e)}`),
    );
  }

  get datagrams(): boolean {
    return this.datagramWriter !== null && this.lastMax > 0;
  }

  get maxDatagramSize(): number {
    return this.datagramWriter ? this.wt.datagrams.maxDatagramSize : 0;
  }

  attach(sink: CarrierSink): void {
    this.sink = sink;
    const queued = this.pending;
    this.pending = [];
    for (const p of queued) this.deliver(p);
    if (this.ended) sink.closed("closed before attach");
  }

  private deliver(p: Pending): void {
    const sink = this.sink;
    if (!sink) {
      this.pending.push(p);
      return;
    }
    switch (p.kind) {
      case "control":
      case "datagram":
        sink.message(p.kind, p.data);
        break;
      case "uni":
        sink.uni(p.stream, p.data);
        break;
      case "uni-end":
        sink.uniEnd(p.stream);
        break;
    }
  }

  private readLoops(controlBidi: WebTransportBidiLike): void {
    readAll(controlBidi.readable, (data) => {
      this.stats.received++;
      this.deliver({ kind: "control", data });
    }).then(
      () => this.end("control bidi ended"),
      (e: unknown) => this.end(`control bidi failed: ${String(e)}`),
    );
    if (this.datagramWriter) {
      readAll(this.wt.datagrams.readable, (data) => {
        this.stats.received++;
        this.deliver({ kind: "datagram", data });
      }).catch(() => {
        // The session's end is reported through `closed`.
      });
    }
    readEach(this.wt.incomingUnidirectionalStreams, (s) => {
      const stream = this.nextStream++;
      readAll(s, (data) => {
        this.stats.received++;
        this.deliver({ kind: "uni", stream, data });
      }).then(
        () => this.deliver({ kind: "uni-end", stream }),
        () => this.deliver({ kind: "uni-end", stream }),
      );
    }).catch(() => {
      // As above.
    });
  }

  private end(reason: string): void {
    if (this.ended) return;
    this.ended = true;
    this.sink?.closed(reason);
  }

  send(out: CarrierOutput): void {
    if (this.ended) return;
    switch (out.type) {
      case "control":
        this.stats.sent++;
        this.control.write(out.data).catch((e: unknown) => this.end(`control write: ${String(e)}`));
        return;
      case "datagram":
        this.sendDatagram(out.data);
        return;
      case "uni-open":
        this.openUni(out.tunnelId, out.prelude);
        return;
      case "uni-chunk":
        this.writeUni(out.tunnelId, out.data);
        return;
      case "uni-finish": {
        const u = this.uniOut.get(out.tunnelId);
        this.uniOut.delete(out.tunnelId);
        if (u) {
          u.chain = u.chain
            .then(async () => {
              const w = await u.writer;
              await w?.close();
            })
            .catch(() => {});
        }
        return;
      }
      case "close":
        this.close("closed by the uplink");
        return;
      case "ws":
        throw new Error("a WebSocket message on a WebTransport carrier");
    }
  }

  private sendDatagram(data: Uint8Array): void {
    const writer = this.datagramWriter;
    if (!writer) {
      this.stats.dropped++;
      return;
    }
    // The limit is read at run time (LS-5 finding 5). A datagram built for
    // an older, larger limit is dropped here rather than by the browser,
    // and the engine sizes the next ones to the new limit.
    const max = this.wt.datagrams.maxDatagramSize;
    if (max !== this.lastMax) {
      this.lastMax = max;
      this.sink?.maxDatagramSize(max);
    }
    if (data.byteLength > max) {
      this.stats.dropped++;
      return;
    }
    // A full queue drops, as a router under load drops: IP tolerates loss.
    // The bound is the carrier's own, not the stream's high-water mark,
    // which in a browser may be a single datagram.
    if (this.datagramsInFlight >= this.maxQueued) {
      this.stats.dropped++;
      return;
    }
    this.stats.sent++;
    this.datagramsInFlight++;
    writer.write(data).then(
      () => {
        this.datagramsInFlight--;
      },
      () => {
        this.datagramsInFlight--;
        this.stats.dropped++;
      },
    );
  }

  private openUni(tunnelId: number, prelude: Uint8Array): void {
    const writer = (async () => {
      const stream = await this.wt.createUnidirectionalStream();
      const w = stream.getWriter();
      // The prelude alone, and awaited, before any chunk.
      await w.write(prelude);
      return w;
    })().catch(() => null);
    this.uniOut.set(tunnelId, {
      writer,
      chain: writer.then(() => {}),
      queued: 0,
    });
  }

  private writeUni(tunnelId: number, data: Uint8Array): void {
    const u = this.uniOut.get(tunnelId);
    if (!u || u.queued >= this.maxQueued) {
      this.stats.dropped++;
      return;
    }
    u.queued++;
    this.stats.sent++;
    u.chain = u.chain
      .then(async () => {
        const w = await u.writer;
        if (!w) throw new Error("uni stream did not open");
        await w.write(data);
      })
      .catch(() => {
        this.stats.dropped++;
      })
      .finally(() => {
        u.queued--;
      });
  }

  close(reason = "closed"): void {
    if (!this.ended) {
      try {
        this.wt.close({ closeCode: 0, reason });
      } catch {
        // already closed
      }
    }
    this.end(reason);
  }
}
