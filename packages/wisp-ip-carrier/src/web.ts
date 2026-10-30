// The parts of the browser's WebTransport and WebSocket APIs the carriers
// use, as structural types. The browser's own objects satisfy them; tests
// pass fakes, and Node (which has WebSocket but no WebTransport) passes its
// global WebSocket.

export interface WebTransportBidiLike {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
}

export interface WebTransportDatagramsLike {
  readonly readable: ReadableStream<Uint8Array>;
  readonly writable: WritableStream<Uint8Array>;
  /**
   * Largest datagram the session sends. Chrome 154 reports a fixed 1024
   * (`datagram_duplex_stream.h`); a datagram above it is dropped without
   * an error, so the carrier reads it before every send.
   */
  readonly maxDatagramSize: number;
}

export interface WebTransportLike {
  readonly ready: Promise<unknown>;
  readonly closed: Promise<unknown>;
  readonly datagrams: WebTransportDatagramsLike;
  readonly incomingUnidirectionalStreams: ReadableStream<ReadableStream<Uint8Array>>;
  createBidirectionalStream(): Promise<WebTransportBidiLike>;
  createUnidirectionalStream(): Promise<WritableStream<Uint8Array>>;
  close(info?: { closeCode?: number; reason?: string }): void;
}

export interface WebTransportHash {
  algorithm: string;
  value: ArrayBuffer | ArrayBufferView;
}

export type WebTransportConstructor = new (
  url: string,
  options?: { serverCertificateHashes?: WebTransportHash[]; allowPooling?: boolean },
) => WebTransportLike;

export interface WebSocketMessageLike {
  readonly data: unknown;
}

export interface WebSocketLike {
  binaryType: string;
  readonly readyState: number;
  readonly bufferedAmount: number;
  readonly protocol: string;
  send(data: Uint8Array): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: "open", listener: () => void): void;
  addEventListener(type: "error", listener: (event: unknown) => void): void;
  addEventListener(
    type: "close",
    listener: (event: { code?: number; reason?: string }) => void,
  ): void;
  addEventListener(type: "message", listener: (event: WebSocketMessageLike) => void): void;
}

export type WebSocketConstructor = new (url: string, protocols?: string | string[]) => WebSocketLike;

export const WS_OPEN = 1;

/** Reads `stream` to its end, calling `chunk` for each piece. */
export async function readAll(
  stream: ReadableStream<Uint8Array>,
  chunk: (data: Uint8Array) => void,
): Promise<void> {
  const reader = stream.getReader();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      if (value && value.byteLength > 0) chunk(value);
    }
  } finally {
    reader.releaseLock();
  }
}

/** Reads every item of `stream`, calling `item` for each. */
export async function readEach<T>(stream: ReadableStream<T>, item: (value: T) => void): Promise<void> {
  const reader = stream.getReader();
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      item(value as T);
    }
  } finally {
    reader.releaseLock();
  }
}

/** `promise`, or a rejection after `ms`. */
export function withTimeout<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${what} timed out after ${ms} ms`)), ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e: unknown) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}
