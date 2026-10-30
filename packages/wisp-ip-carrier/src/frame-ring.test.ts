import { describe, expect, test } from "bun:test";
import { MemoryFrameRing } from "./frame-ring.js";
import { tick } from "./test-support.js";

describe("memory frame ring", () => {
  test("frames cross in order, outside the caller", async () => {
    const [uplink, wire] = MemoryFrameRing.pair(8);
    const got: number[] = [];
    let inside = false;
    wire.onFrame((f) => {
      expect(inside).toBe(false);
      got.push(f[0]);
    });
    inside = true;
    expect(uplink.push(Uint8Array.of(1))).toBe(true);
    expect(uplink.push(Uint8Array.of(2))).toBe(true);
    inside = false;
    expect(got).toEqual([]);
    await tick();
    expect(got).toEqual([1, 2]);
    expect(uplink.stats.pushed).toBe(2);
    expect(wire.stats.delivered).toBe(2);
  });

  test("the ring keeps its own copy", async () => {
    const [a, b] = MemoryFrameRing.pair();
    const buf = Uint8Array.of(5, 5);
    a.push(buf);
    buf[0] = 9;
    const got: Uint8Array[] = [];
    b.onFrame((f) => got.push(f));
    await tick();
    expect([...got[0]]).toEqual([5, 5]);
  });

  test("a full ring drops, as a receive ring does", async () => {
    const [a, b] = MemoryFrameRing.pair(2);
    expect(a.push(Uint8Array.of(1))).toBe(true);
    expect(a.push(Uint8Array.of(2))).toBe(true);
    expect(a.push(Uint8Array.of(3))).toBe(false);
    expect(a.stats.dropped).toBe(1);
    expect(b.waiting).toBe(2);
    const got: number[] = [];
    b.onFrame((f) => got.push(f[0]));
    await tick();
    expect(got).toEqual([1, 2]);
    expect(a.push(Uint8Array.of(4))).toBe(true);
  });

  test("a closed end takes nothing", () => {
    const [a, b] = MemoryFrameRing.pair();
    b.close();
    expect(a.push(Uint8Array.of(1))).toBe(false);
    a.close();
    expect(a.push(Uint8Array.of(1))).toBe(false);
  });
});
