// Fakes for the tests: a WebTransport session whose server side the test
// drives, and a scripted carrier.

import type { Carrier, CarrierOutput, CarrierSink, CarrierStats } from "./carrier.js";
import type {
  WebTransportBidiLike,
  WebTransportDatagramsLike,
  WebTransportLike,
} from "./web.js";

function source<T>(): { stream: ReadableStream<T>; push(v: T): void; end(): void } {
  let ctl!: ReadableStreamDefaultController<T>;
  const stream = new ReadableStream<T>({
    start(c) {
      ctl = c;
    },
  });
  return { stream, push: (v) => ctl.enqueue(v), end: () => ctl.close() };
}

export interface RecordedStream {
  writes: Uint8Array[];
  closed: boolean;
}

function sink(rec: RecordedStream, delayMs = 0): WritableStream<Uint8Array> {
  return new WritableStream<Uint8Array>({
    async write(chunk) {
      if (delayMs > 0) await new Promise((r) => setTimeout(r, delayMs));
      rec.writes.push(chunk.slice());
    },
    close() {
      rec.closed = true;
    },
  });
}

export class FakeWebTransport implements WebTransportLike {
  static last: FakeWebTransport | null = null;
  readonly ready: Promise<void>;
  readonly closed: Promise<void>;
  readonly datagrams: WebTransportDatagramsLike & { maxDatagramSize: number };
  readonly incomingUnidirectionalStreams: ReadableStream<ReadableStream<Uint8Array>>;
  readonly control: RecordedStream = { writes: [], closed: false };
  readonly sentDatagrams: RecordedStream = { writes: [], closed: false };
  readonly uniOut: RecordedStream[] = [];
  bidis = 0;
  closeInfo: { closeCode?: number; reason?: string } | null = null;
  private readonly controlIn = source<Uint8Array>();
  private readonly datagramsIn = source<Uint8Array>();
  private readonly unisIn = source<ReadableStream<Uint8Array>>();
  private resolveClosed!: () => void;
  private resolveReady!: () => void;
  private rejectReady!: (e: unknown) => void;

  constructor(
    readonly url: string,
    readonly options?: unknown,
  ) {
    FakeWebTransport.last = this;
    this.ready = new Promise((res, rej) => {
      this.resolveReady = res;
      this.rejectReady = rej;
    });
    this.closed = new Promise((res) => {
      this.resolveClosed = res;
    });
    this.datagrams = {
      readable: this.datagramsIn.stream,
      writable: sink(this.sentDatagrams),
      maxDatagramSize: 1024,
    };
    this.incomingUnidirectionalStreams = this.unisIn.stream;
    if (FakeWebTransport.autoReady) queueMicrotask(() => this.resolveReady());
  }

  /** Whether new sessions become ready on their own. */
  static autoReady = true;

  open(): void {
    this.resolveReady();
  }

  fail(e: unknown): void {
    this.rejectReady(e);
  }

  async createBidirectionalStream(): Promise<WebTransportBidiLike> {
    this.bidis++;
    return { readable: this.controlIn.stream, writable: sink(this.control) };
  }

  async createUnidirectionalStream(): Promise<WritableStream<Uint8Array>> {
    const rec: RecordedStream = { writes: [], closed: false };
    this.uniOut.push(rec);
    return sink(rec, 1);
  }

  close(info?: { closeCode?: number; reason?: string }): void {
    this.closeInfo = info ?? {};
    this.resolveClosed();
  }

  // The server's side.
  serverControl(data: Uint8Array): void {
    this.controlIn.push(data);
  }

  serverDatagram(data: Uint8Array): void {
    this.datagramsIn.push(data);
  }

  serverUni(): { push(d: Uint8Array): void; end(): void } {
    const s = source<Uint8Array>();
    this.unisIn.push(s.stream);
    return { push: s.push, end: s.end };
  }

  serverClose(): void {
    this.resolveClosed();
  }
}

/** A carrier the test scripts: it records what it is sent. */
export class ScriptedCarrier implements Carrier {
  readonly stats: CarrierStats = { sent: 0, received: 0, dropped: 0 };
  readonly sent: CarrierOutput[] = [];
  sink: CarrierSink | null = null;
  closedWith: string | null = null;

  constructor(
    readonly kind: "webtransport" | "websocket",
    readonly datagrams = false,
    readonly maxDatagramSize = 0,
  ) {}

  attach(sink: CarrierSink): void {
    this.sink = sink;
  }

  send(out: CarrierOutput): void {
    this.sent.push(out);
  }

  close(reason = "closed"): void {
    if (this.closedWith !== null) return;
    this.closedWith = reason;
    this.sink?.closed(reason);
  }

  /** What arrives from the relay. */
  receive(data: Uint8Array): void {
    this.sink?.message(this.kind === "websocket" ? "ws" : "control", data);
  }

  take(): CarrierOutput[] {
    return this.sent.splice(0);
  }
}

export function hex(s: string): Uint8Array {
  const clean = s.replace(/\s+/g, "");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export const tick = () => new Promise((r) => setTimeout(r, 0));

export async function until(cond: () => boolean, ms = 2000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error("condition not reached");
    await new Promise((r) => setTimeout(r, 2));
  }
}
