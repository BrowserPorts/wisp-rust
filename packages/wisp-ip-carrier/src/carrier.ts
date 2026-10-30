// What every carrier does for the uplink engine: move the bytes of one Wisp
// connection. The engine (the `wisp-ip-client` crate) decides what they mean.

export type CarrierKind = "webtransport" | "websocket";

/** What the engine asks a carrier to send. */
export type CarrierOutput =
  /** One binary WebSocket message: one Wisp v2 packet. */
  | { type: "ws"; data: Uint8Array }
  /** Bytes for the wisp-wt control bidi. */
  | { type: "control"; data: Uint8Array }
  /** One WebTransport datagram. */
  | { type: "datagram"; data: Uint8Array }
  /**
   * Open the uni stream for `tunnelId` and write `prelude` on it as a write
   * of its own, before any chunk (LS-5 finding 1: the relay's pinned h3
   * parses a uni stream's session id only once more bytes follow).
   */
  | { type: "uni-open"; tunnelId: number; prelude: Uint8Array }
  /** One `[length:u16][packet]` chunk for `tunnelId`'s uni stream. */
  | { type: "uni-chunk"; tunnelId: number; data: Uint8Array }
  | { type: "uni-finish"; tunnelId: number }
  /** End the connection. */
  | { type: "close" };

/** Where a carrier delivers what it receives. */
export interface CarrierSink {
  /** A WebSocket message, control bidi bytes, or a datagram. */
  message(channel: "ws" | "control" | "datagram", data: Uint8Array): void;
  /** Bytes of an incoming uni stream, numbered by the carrier. */
  uni(stream: number, data: Uint8Array): void;
  uniEnd(stream: number): void;
  /** The session's `maxDatagramSize` changed. */
  maxDatagramSize(size: number): void;
  /** The connection ended. Called once. */
  closed(reason: string): void;
}

export interface CarrierStats {
  sent: number;
  received: number;
  /** Datagrams or packets dropped under backpressure or above the limit. */
  dropped: number;
}

export interface Carrier {
  readonly kind: CarrierKind;
  /** Whether packets can ride datagrams. */
  readonly datagrams: boolean;
  /** The live datagram limit; 0 on WebSocket. */
  readonly maxDatagramSize: number;
  readonly stats: CarrierStats;
  /** Starts delivering to `sink`. What arrived before is delivered first. */
  attach(sink: CarrierSink): void;
  send(out: CarrierOutput): void;
  close(reason?: string): void;
}

/** This environment has no such transport (Node has no WebTransport). */
export class CarrierUnavailable extends Error {
  override name = "CarrierUnavailable";
}
