// wisp-ip-carrier: the carriers of the IP_TUNNEL uplink (Wisp extension
// 0xF3) for the uplink Worker. WebTransport datagrams first, WebSocket when
// UDP to the relay is blocked (decision LD1), a frame ring to the
// netkernel's wire device, and the loop that drives the `wisp-ip-client`
// engine between them.

export {
  type Carrier,
  type CarrierKind,
  type CarrierOutput,
  type CarrierSink,
  type CarrierStats,
  CarrierUnavailable,
} from "./carrier.js";
export {
  WasmUplinkEngine,
  decodeEvent,
  decodeOutput,
  encodeEngineConfig,
  type EngineConfig,
  type EngineOutput,
  type LinkConfig,
  type UplinkEngine,
  type UplinkEvent,
  type WasmEngineExports,
} from "./engine.js";
export { type FrameRing, type FrameRingStats, MemoryFrameRing } from "./frame-ring.js";
export { DEFAULT_HEAD_START_MS, type HappyEyeballsOptions, happyEyeballs } from "./happy-eyeballs.js";
export { UplinkRunner, type UplinkOptions } from "./uplink.js";
export {
  WISP_V2_PROTOCOL,
  WebSocketCarrier,
  type WebSocketCarrierOptions,
} from "./websocket.js";
export { WebTransportCarrier, type WebTransportCarrierOptions } from "./webtransport.js";
export type {
  WebSocketConstructor,
  WebSocketLike,
  WebTransportConstructor,
  WebTransportLike,
} from "./web.js";
