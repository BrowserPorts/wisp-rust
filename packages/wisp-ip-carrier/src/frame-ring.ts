// The frame ring between the uplink and the netkernel's wire device: the
// Ethernet II frames of `eth0` (destination, source, type, payload; no
// frame check sequence, no virtio header), one per entry, in each
// direction. The netkernel's side (`tools/lkl/wasm/wire_netdev.c` and the
// host package's carrier, LS-4) is not built yet; this is the interface the
// uplink needs, with the in-memory pair tests and single-thread hosts use.

export interface FrameRing {
  /**
   * Delivers each frame the wire device transmits (the machine's outgoing
   * traffic). `null` stops delivery; frames then wait, up to the ring's
   * capacity.
   */
  onFrame(handler: ((frame: Uint8Array) => void) | null): void;
  /**
   * Hands one frame to the wire device (the machine's incoming traffic).
   * `false` when it was dropped: the ring is full or closed, as a NIC's
   * receive ring drops.
   */
  push(frame: Uint8Array): boolean;
  close(): void;
}

export interface FrameRingStats {
  pushed: number;
  delivered: number;
  dropped: number;
}

/**
 * One end of an in-memory ring pair. Frames pushed on one end are delivered
 * to the other end's handler from a microtask, never inside `push`, so a
 * handler that answers at once does not re-enter its caller.
 */
export class MemoryFrameRing implements FrameRing {
  readonly stats: FrameRingStats = { pushed: 0, delivered: 0, dropped: 0 };
  private handler: ((frame: Uint8Array) => void) | null = null;
  private queue: Uint8Array[] = [];
  private scheduled = false;
  private closed = false;
  private peer: MemoryFrameRing | null = null;

  private constructor(private readonly capacity: number) {}

  /** Two connected ends, each holding at most `capacity` undelivered frames. */
  static pair(capacity = 256): [MemoryFrameRing, MemoryFrameRing] {
    const a = new MemoryFrameRing(capacity);
    const b = new MemoryFrameRing(capacity);
    a.peer = b;
    b.peer = a;
    return [a, b];
  }

  /** Frames waiting for this end's handler. */
  get waiting(): number {
    return this.queue.length;
  }

  onFrame(handler: ((frame: Uint8Array) => void) | null): void {
    this.handler = handler;
    this.schedule();
  }

  push(frame: Uint8Array): boolean {
    const peer = this.peer;
    if (this.closed || !peer || peer.closed || peer.queue.length >= peer.capacity) {
      this.stats.dropped++;
      return false;
    }
    this.stats.pushed++;
    // The ring owns its copy: the caller may reuse its buffer.
    peer.queue.push(frame.slice());
    peer.schedule();
    return true;
  }

  private schedule(): void {
    if (this.scheduled || !this.handler || this.queue.length === 0) return;
    this.scheduled = true;
    queueMicrotask(() => {
      this.scheduled = false;
      while (this.handler && this.queue.length > 0) {
        const f = this.queue.shift() as Uint8Array;
        this.stats.delivered++;
        this.handler(f);
      }
    });
  }

  close(): void {
    this.closed = true;
    this.queue = [];
    this.handler = null;
  }
}
