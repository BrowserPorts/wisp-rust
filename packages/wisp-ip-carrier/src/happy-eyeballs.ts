// Which carrier the uplink uses (decision LD1): WebTransport first, since
// its datagrams have no head-of-line blocking and no nested retransmission;
// WebSocket when UDP to the relay is blocked. As in Happy Eyeballs (RFC
// 8305), the preferred attempt gets a head start and the fallback starts
// when the head start runs out or the preferred attempt fails, whichever is
// first. The first carrier to connect wins; a later one is closed.

import type { Carrier } from "./carrier.js";

export interface HappyEyeballsOptions {
  /** Starts the WebTransport attempt; omitted where there is none (Node). */
  webTransport?: () => Promise<Carrier>;
  /** Starts the WebSocket attempt. */
  webSocket?: () => Promise<Carrier>;
  /** Head start of the WebTransport attempt (RFC 8305's 250 ms, rounded up). */
  headStartMs?: number;
}

export const DEFAULT_HEAD_START_MS = 300;

/** The first carrier to connect. Rejects with every attempt's error. */
export function happyEyeballs(options: HappyEyeballsOptions): Promise<Carrier> {
  const { webTransport, webSocket } = options;
  const headStart = options.headStartMs ?? DEFAULT_HEAD_START_MS;
  return new Promise<Carrier>((resolve, reject) => {
    let settled = false;
    let running = 0;
    let wsStarted = false;
    const errors: unknown[] = [];
    let timer: ReturnType<typeof setTimeout> | undefined;

    const win = (c: Carrier) => {
      running--;
      if (settled) {
        c.close("another carrier connected first");
        return;
      }
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      resolve(c);
    };
    const lose = (e: unknown) => {
      running--;
      errors.push(e);
      if (!settled && running === 0 && (wsStarted || !webSocket)) {
        settled = true;
        if (timer !== undefined) clearTimeout(timer);
        reject(new AggregateError(errors, "no carrier connected"));
      }
    };
    const startWebSocket = () => {
      if (wsStarted || settled || !webSocket) return;
      wsStarted = true;
      running++;
      webSocket().then(win, lose);
    };

    if (!webTransport && !webSocket) {
      reject(new Error("no carrier to try"));
      return;
    }
    if (webTransport) {
      running++;
      webTransport().then(win, (e: unknown) => {
        lose(e);
        startWebSocket();
      });
      timer = setTimeout(startWebSocket, headStart);
    } else {
      startWebSocket();
    }
  });
}
