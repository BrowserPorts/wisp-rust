import { afterEach, describe, expect, test } from "bun:test";
import type { CarrierSink } from "./carrier.js";
import { CarrierUnavailable } from "./carrier.js";
import { FakeWebTransport, until } from "./test-support.js";
import type { WebTransportConstructor } from "./web.js";
import { WebTransportCarrier } from "./webtransport.js";

const WT = FakeWebTransport as unknown as WebTransportConstructor;

function recorder() {
  const got = {
    control: [] as Uint8Array[],
    datagrams: [] as Uint8Array[],
    uni: [] as [number, Uint8Array][],
    uniEnd: [] as number[],
    limits: [] as number[],
    closed: [] as string[],
  };
  const sink: CarrierSink = {
    message: (ch, d) => {
      if (ch === "control") got.control.push(d);
      else if (ch === "datagram") got.datagrams.push(d);
    },
    uni: (s, d) => got.uni.push([s, d]),
    uniEnd: (s) => got.uniEnd.push(s),
    maxDatagramSize: (n) => got.limits.push(n),
    closed: (r) => got.closed.push(r),
  };
  return { got, sink };
}

afterEach(() => {
  FakeWebTransport.autoReady = true;
});

describe("WebTransport carriage", () => {
  test("opens the session and its control bidi", async () => {
    const c = await WebTransportCarrier.connect("https://relay.test/wisp-wt", { WebTransport: WT });
    const wt = FakeWebTransport.last as FakeWebTransport;
    expect(wt.bidis).toBe(1);
    expect(c.datagrams).toBe(true);
    expect(c.maxDatagramSize).toBe(1024);
    // Control bytes from before the attach are kept.
    wt.serverControl(Uint8Array.of(1, 0, 0, 0, 2));
    await until(() => true);
    const { got, sink } = recorder();
    c.attach(sink);
    c.send({ type: "control", data: Uint8Array.of(9, 9) });
    await until(() => got.control.length === 1 && wt.control.writes.length === 1);
    expect([...got.control[0]]).toEqual([1, 0, 0, 0, 2]);
    expect([...wt.control.writes[0]]).toEqual([9, 9]);
  });

  test("is unavailable without WebTransport", async () => {
    await expect(WebTransportCarrier.connect("https://relay.test/")).rejects.toBeInstanceOf(
      CarrierUnavailable,
    );
  });

  test("gives up when the session does not come up in time", async () => {
    FakeWebTransport.autoReady = false;
    await expect(
      WebTransportCarrier.connect("https://relay.test/", { WebTransport: WT, timeoutMs: 20 }),
    ).rejects.toThrow("timed out");
    expect((FakeWebTransport.last as FakeWebTransport).closeInfo).not.toBeNull();
  });

  test("reads the datagram limit before every send", async () => {
    const c = await WebTransportCarrier.connect("https://relay.test/", { WebTransport: WT });
    const wt = FakeWebTransport.last as FakeWebTransport;
    const { got, sink } = recorder();
    c.attach(sink);
    c.send({ type: "datagram", data: new Uint8Array(1024) });
    c.send({ type: "datagram", data: new Uint8Array(1025) });
    await until(() => wt.sentDatagrams.writes.length === 1);
    expect(c.stats.dropped).toBe(1);
    expect(got.limits).toEqual([]);
    // The browser lowers its limit: the carrier tells the engine and drops
    // what no longer fits instead of letting the browser drop it silently.
    wt.datagrams.maxDatagramSize = 900;
    c.send({ type: "datagram", data: new Uint8Array(1000) });
    expect(got.limits).toEqual([900]);
    expect(c.stats.dropped).toBe(2);
    wt.serverDatagram(Uint8Array.of(2, 2, 1, 0, 0, 0, 0));
    await until(() => got.datagrams.length === 1);
  });

  test("writes a uni stream's prelude alone, then its chunks in order", async () => {
    const c = await WebTransportCarrier.connect("https://relay.test/", { WebTransport: WT });
    const wt = FakeWebTransport.last as FakeWebTransport;
    c.attach(recorder().sink);
    c.send({ type: "uni-open", tunnelId: 1, prelude: Uint8Array.of(1, 0, 0, 0) });
    for (let i = 0; i < 3; i++) {
      c.send({ type: "uni-chunk", tunnelId: 1, data: Uint8Array.of(1, 0, i) });
    }
    c.send({ type: "uni-finish", tunnelId: 1 });
    await until(() => wt.uniOut[0]?.closed === true);
    expect(wt.uniOut[0].writes.map((w) => [...w])).toEqual([
      [1, 0, 0, 0],
      [1, 0, 0],
      [1, 0, 1],
      [1, 0, 2],
    ]);
    // A chunk for a stream that was never opened is dropped.
    c.send({ type: "uni-chunk", tunnelId: 2, data: Uint8Array.of(0, 0) });
    expect(c.stats.dropped).toBe(1);
  });

  test("numbers incoming uni streams and reports their end", async () => {
    const c = await WebTransportCarrier.connect("https://relay.test/", { WebTransport: WT });
    const wt = FakeWebTransport.last as FakeWebTransport;
    const { got, sink } = recorder();
    c.attach(sink);
    const a = wt.serverUni();
    const b = wt.serverUni();
    a.push(Uint8Array.of(7, 0, 0, 0));
    b.push(Uint8Array.of(8, 0, 0, 0));
    a.end();
    await until(() => got.uni.length === 2 && got.uniEnd.length === 1);
    const streams = new Set(got.uni.map(([s]) => s));
    expect(streams.size).toBe(2);
    expect(got.uniEnd[0]).toBe(got.uni.find(([, d]) => d[0] === 7)?.[0] as number);
  });

  test("reports the session's end once", async () => {
    const c = await WebTransportCarrier.connect("https://relay.test/", { WebTransport: WT });
    const wt = FakeWebTransport.last as FakeWebTransport;
    const { got, sink } = recorder();
    c.attach(sink);
    wt.serverClose();
    await until(() => got.closed.length === 1);
    c.close();
    c.send({ type: "datagram", data: new Uint8Array(10) });
    expect(got.closed.length).toBe(1);
    expect(wt.sentDatagrams.writes.length).toBe(0);
  });
});
