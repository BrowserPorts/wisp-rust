import { describe, expect, test } from "bun:test";
import type { Carrier } from "./carrier.js";
import { happyEyeballs } from "./happy-eyeballs.js";
import { ScriptedCarrier } from "./test-support.js";

function after<T>(ms: number, value: () => T): Promise<T> {
  return new Promise((resolve, reject) =>
    setTimeout(() => {
      try {
        resolve(value());
      } catch (e) {
        reject(e);
      }
    }, ms),
  );
}

describe("happy eyeballs", () => {
  test("WebTransport wins when it connects within its head start", async () => {
    const wt = new ScriptedCarrier("webtransport", true, 1024);
    let wsTried = false;
    const c = await happyEyeballs({
      webTransport: () => after(20, () => wt),
      webSocket: () => {
        wsTried = true;
        return after(0, () => new ScriptedCarrier("websocket"));
      },
      headStartMs: 100,
    });
    expect(c).toBe(wt);
    await after(150, () => 0);
    expect(wsTried).toBe(false);
  });

  test("WebSocket starts after the head start and the slower carrier is closed", async () => {
    const wt = new ScriptedCarrier("webtransport", true, 1024);
    const ws = new ScriptedCarrier("websocket");
    const started: number[] = [];
    const t0 = Date.now();
    const c = await happyEyeballs({
      webTransport: () => after(200, () => wt),
      webSocket: () => {
        started.push(Date.now() - t0);
        return after(10, () => ws);
      },
      headStartMs: 50,
    });
    expect(c).toBe(ws);
    expect(started[0]).toBeGreaterThanOrEqual(45);
    await after(220, () => 0);
    expect(wt.closedWith).toBe("another carrier connected first");
  });

  test("a failed WebTransport attempt starts WebSocket at once", async () => {
    const t0 = Date.now();
    const c = await happyEyeballs({
      webTransport: () => Promise.reject(new Error("UDP blocked")),
      webSocket: () => after(0, () => new ScriptedCarrier("websocket")),
      headStartMs: 5_000,
    });
    expect(c.kind).toBe("websocket");
    expect(Date.now() - t0).toBeLessThan(1_000);
  });

  test("without WebTransport (Node) only WebSocket is tried", async () => {
    const c = await happyEyeballs({
      webSocket: () => after(0, () => new ScriptedCarrier("websocket")),
    });
    expect(c.kind).toBe("websocket");
  });

  test("rejects with every error when nothing connects", async () => {
    const p: Promise<Carrier> = happyEyeballs({
      webTransport: () => Promise.reject(new Error("wt down")),
      webSocket: () => after(5, () => {
        throw new Error("ws down");
      }),
      headStartMs: 10,
    });
    try {
      await p;
      throw new Error("resolved");
    } catch (e) {
      expect(e).toBeInstanceOf(AggregateError);
      expect((e as AggregateError).errors.map((x: Error) => x.message)).toEqual([
        "wt down",
        "ws down",
      ]);
    }
  });
});
