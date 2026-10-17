import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import type { IncomingMessage, ServerResponse } from "node:http";
import { connect as connectTcp, createServer } from "node:net";
import { resolve } from "node:path";
import type { Duplex } from "node:stream";
import { connect as connectTls } from "node:tls";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import type { TomlTable, TomlValue } from "smol-toml";
import type { Plugin, ProxyOptions, UserConfig } from "vite";
import {
  EDGE_SECRET_HEADER,
  ProxyRejection,
  WebSocketLimiter,
  assertSameOrigin,
  buildUpstreamRequestHeaders,
  buildUpstreamSocketHeaders,
  buildUpstreamUrl,
  canonicalIp,
  createEdgeTrust,
  filterUpstreamResponseHeaders,
  forwardableCloseCode,
  generateEdgeSecret,
  isAuthorityPath,
  isTrustedEdgePeer,
  mirroredRejectionStatus,
  positiveIntegerEnv,
  probeUpstreamStatus,
  resolveCanonicalClientIp,
  truncateCloseReason,
} from "./front-proxy.js";
import type { EdgeTrust, WebSocketSlot } from "./front-proxy.js";

export type WispRuntimeInput =
  | {
      tomlPath?: string;
      toml?: string;
      source?: string;
      config?: Record<string, unknown>;
      logLevel?: string;
    }
  | Record<string, unknown>;

export type ProxyRouteInput = {
  routeId: string;
  domains?: string[];
  targetUrls?: string[];
  provider?: string;
  country?: string;
  city?: string;
  ipType?: string;
};

export type ProxyRuntimePolicy = {
  forceProxy?: boolean;
  defaultProvider?: string;
  defaultCountry?: string;
  defaultCity?: string;
  defaultIpType?: string;
};

export type WispHostPortRule = {
  host: string;
  port: number;
};

export type WispAuthTokenPolicy = {
  limitProfile?: string;
  allowedProxyProviders?: string[];
  domainBlacklist?: string[];
  domainWhitelist?: string[];
  hostnameBlacklist?: string[];
  hostnameWhitelist?: string[];
  ipBlacklist?: string[];
  ipWhitelist?: string[];
  portBlacklist?: number[];
  portWhitelist?: number[];
  hostPortWhitelist?: WispHostPortRule[];
  allowDirectIp?: boolean;
  allowPrivateIps?: boolean;
  allowLoopbackIps?: boolean;
};

export type WispAuthTokenHandlerResult =
  | WispAuthTokenPolicy
  | boolean
  | null
  | undefined;

export type WispAuthTokenHandler = (
  token: string,
) => WispAuthTokenHandlerResult | Promise<WispAuthTokenHandlerResult>;

export type WispRust = {
  start(): Promise<RuntimeStatus>;
  stop(): Promise<RuntimeStatus>;
  status(): RuntimeStatus;
  boundUrls(): string[];
  setRoute(route: ProxyRouteInput): Promise<RuntimeResult>;
  removeRoute(routeId: string): RuntimeResult;
  listRoutes(): RuntimeResult[];
  rotateRoute(routeId: string): Promise<RuntimeResult | null>;
  locations(provider?: string): Promise<RuntimeResult>;
  refreshLocations(provider?: string): Promise<RuntimeResult>;
  providerStatus(): RuntimeResult;
  egressInventory(): RuntimeResult;
  blockEgressIp(ip: string): RuntimeResult;
  releaseEgressIp(ip: string): RuntimeResult;
  getPolicy(): ProxyRuntimePolicy;
  setPolicy(policy: ProxyRuntimePolicy): ProxyRuntimePolicy;
  getLimits(): RuntimeResult;
  patchLimits(patch: RuntimeResult): RuntimeResult;
  setLimitProfile(name: string, limits: RuntimeResult): RuntimeResult;
  patchLimitProfile(name: string, patch: RuntimeResult): RuntimeResult;
  limitProfile(name: string): RuntimeResult | null;
  listLimitProfiles(): RuntimeResult[];
  setAuthTokenHandler(handler?: WispAuthTokenHandler): RuntimeResult;
  registerAuthToken(token: string, policy: WispAuthTokenPolicy): RuntimeResult;
  revokeAuthToken(token: string): RuntimeResult;
  listAuthTokens(): RuntimeResult[];
  authTokenPolicy(token: string): WispAuthTokenPolicy | null;
};

export type WispRustNativeModule = {
  WispRust: {
    new (): WispRust;
    fromTomlPath(path: string): WispRust;
    fromToml(toml: string, source?: string): WispRust;
    fromConfig(config: WispRuntimeInput): WispRust;
  };
};

export type WispRustRuntimeOptions = {
  tomlPath?: string;
  toml?: string;
  source?: string;
  proxyConfigPath?: string;
  authenticatedProxyConfigPath?: string;
  authenticatedLimitMultiplier?: number;
  authenticatedProfileName?: string;
  authTokenHandler?: WispAuthTokenHandler;
  authenticatedAllowedProxyProviders?: string[];
  config?: WispRuntimeInput;
  logLevel?: string;
  cwd?: string;
  native?: WispRustNativeModule;
  resolvedWsPort?: number;
  trustedBunFront?: boolean;
  /**
   * Secret the native listener requires from the front in trusted_edge mode. Generated per
   * process when trustedBunFront is set and this is left out.
   */
  trustedEdgeSecret?: string;
};

export type WispRustViteOptions = WispRustRuntimeOptions & {
  proxyPath?: string;
  autoStart?: boolean;
  startInPreview?: boolean;
  stopOnClose?: boolean;
  configureProxy?: (
    proxy: ProxyOptions,
    context: WispRustProxyContext,
  ) => ProxyOptions;
};

export type WispRustProxyContext = {
  boundUrl: URL;
  proxyPath: string;
  endpointPath: string;
  target: string;
  /** Present in trusted_edge mode: the secret the native listener expects on each upgrade */
  edgeSecret?: string;
};

type RuntimeStatus = Record<string, unknown>;
type RuntimeResult = Record<string, unknown>;
type ClosableServer = {
  once(event: "close", listener: () => unknown): unknown;
};
type UpgradeServer = ClosableServer & {
  prependListener(
    event: "upgrade",
    listener: (
      request: IncomingMessage,
      socket: Duplex,
      head: Buffer,
    ) => unknown,
  ): unknown;
};
type BunProxySocket = {
  send(data: string | Buffer): number;
  getBufferedAmount?(): number;
  close(code?: number, reason?: string): unknown;
};
type BunAdapterProxySocketData = {
  open(socket: BunProxySocket): unknown;
  message(socket: BunProxySocket, message: string | Buffer): unknown;
  close(socket: BunProxySocket, code: number, reason: string): unknown;
};
type BunUpgradeApi = {
  upgrade(
    request: Request,
    options: { data: BunAdapterProxySocketData },
  ): boolean;
  requestIP?(request: Request): { address: string } | null;
};
type BunMiddlewareStack = {
  use(
    handler: (
      request: IncomingMessage,
      response: ServerResponse,
      next: () => unknown,
    ) => unknown,
  ): unknown;
};
type TomlRecord = Record<string, TomlValue>;
type ProviderSection = TomlRecord | undefined;

const require = createRequire(import.meta.url);
const DEFAULT_MULLVAD_API = "https://api.mullvad.net/www/relays/wireguard/";
const DEFAULT_MYSTERIUM_API = "https://api.mysteriumvpn.com";
const DEFAULT_AUTHENTICATED_PROFILE = "authenticated";
const DEFAULT_AUTHENTICATED_PROVIDERS = ["mullvad", "resi", "mysterium"];
const MAX_BUN_PENDING_BYTES = 1024 * 1024;
const BUN_UPSTREAM_CONNECT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_WEBSOCKETS = 2048;
const DEFAULT_MAX_WEBSOCKETS_PER_IP = 128;
const DEFAULT_MAX_BUFFERED_BYTES = 4 * 1024 * 1024;
export const DEFAULT_WISP_RUST_VITE_TOML = `
[wisp.server]
endpoint = "/wisp/"
wisp_version = "auto"

[wisp.auth]
required = false

[wisp.destination]
port_whitelist = [80, 443]
allow_direct_ip = true
allow_private_ips = false
allow_loopback_ips = false

[wisp_websocket]
enabled = true
host = "127.0.0.1"
port = 4142
endpoint = "/wisp/"
ingress_mode = "direct_plain"
`;
const MULTIPLIED_LIMIT_FIELDS = new Set([
  "streamLimitPerHost",
  "streamLimitTotal",
  "bufferSize",
  "continueThreshold",
  "maxConnectionsPerIp",
  "maxBinaryFrameBytes",
  "maxTextFrameBytes",
  "maxPendingPacketsPerStream",
  "maxPendingBytesPerStream",
  "maxEgressQueueBytes",
  "maxIngressBytesPerConnection",
  "maxSessionHops",
  "maxDailyHopsPerIp",
  "maxConnectionStartsPerIpPerMinute",
  "maxTcpStreamOpensPerConnectionPerMinute",
  "maxTcpStreamOpensPerIpPerMinute",
  "maxTcpBytesPerConnectionPerSecond",
  "maxTcpBytesPerIpPerSecond",
  "maxDatagramsPerConnectionPerSecond",
  "maxDatagramBytesPerConnectionPerSecond",
  "maxDatagramsPerIpPerSecond",
  "maxDatagramBytesPerIpPerSecond",
  "maxControlMessagesPerConnectionPerMinute",
  "maxControlMessagesPerIpPerMinute",
  "maxBinaryPacketsPerConnectionPerMinute",
  "maxConcurrentProxyControlHandlers",
  "proxyControlExtPayloadMaxBytes",
  "maxProxyRulesPerConnection",
  "maxProxyControlReplyBytes",
  "maxProxyRuleFieldBytes",
  "proxyControlUpstreamOpsPerSecond",
  "proxyControlUpstreamBurst",
  "proxyControlMutationOpsPerSecond",
  "proxyControlMutationBurst",
  "protocolInspectionMaxBytes",
]);

export class WispRustRuntime {
  readonly native: WispRustNativeModule;
  readonly instance: WispRust;
  /** Secret sent on every upgrade to the native listener, set only in trusted_edge mode */
  readonly edgeSecret: string | undefined;

  private startPromise: Promise<RuntimeStatus> | undefined;
  private stopPromise: Promise<RuntimeStatus> | undefined;

  constructor(options: WispRustRuntimeOptions = {}) {
    this.native = options.native ?? loadNative();
    this.edgeSecret = options.trustedBunFront
      ? (options.trustedEdgeSecret ?? generateEdgeSecret())
      : undefined;
    const resolved = this.edgeSecret
      ? { ...options, trustedEdgeSecret: this.edgeSecret }
      : options;
    this.instance = createNativeRuntime(this.native, resolved);
    configureAuthenticatedProfile(this.instance, resolved);
  }

  async start(): Promise<RuntimeStatus> {
    if (!this.startPromise) {
      const pending = this.instance.start();
      this.startPromise = pending.catch((error) => {
        this.startPromise = undefined;
        throw error;
      });
    }
    return this.startPromise;
  }

  async stop(): Promise<RuntimeStatus> {
    if (!this.stopPromise) {
      this.stopPromise = this.instance.stop().finally(() => {
        this.startPromise = undefined;
        this.stopPromise = undefined;
      });
    }
    return this.stopPromise;
  }

  status(): RuntimeStatus {
    return this.instance.status();
  }

  boundUrls(): string[] {
    return this.instance.boundUrls();
  }

  primaryBoundUrl(): URL {
    const [first] = this.boundUrls();
    if (!first) {
      throw new Error("wisp websocket listener is not enabled");
    }
    return new URL(first);
  }

  proxyContext(proxyPath?: string): WispRustProxyContext {
    const boundUrl = this.primaryBoundUrl();
    const endpointPath = normalizeMountPath(boundUrl.pathname);
    const mountPath = normalizeMountPath(proxyPath ?? endpointPath);
    const targetProtocol = boundUrl.protocol === "wss:" ? "https:" : "http:";
    const target = `${targetProtocol}//${boundUrl.host}`;
    return {
      boundUrl,
      proxyPath: mountPath,
      endpointPath,
      target,
      edgeSecret: this.edgeSecret,
    };
  }

  viteProxyOptions(
    options: Pick<WispRustViteOptions, "proxyPath" | "configureProxy"> = {},
  ): {
    path: string;
    options: ProxyOptions;
  } {
    const context = this.proxyContext(options.proxyPath);
    const proxy: ProxyOptions = {
      target: context.target,
      ws: true,
      changeOrigin: true,
      secure: context.boundUrl.protocol === "wss:",
      headers: context.edgeSecret
        ? { [EDGE_SECRET_HEADER]: context.edgeSecret }
        : undefined,
      rewrite:
        context.proxyPath === context.endpointPath
          ? undefined
          : (path) =>
              rewriteMountPath(path, context.proxyPath, context.endpointPath),
    };
    return {
      path: proxyMatchPath(context.proxyPath),
      options: options.configureProxy?.(proxy, context) ?? proxy,
    };
  }

  setRoute(route: ProxyRouteInput): Promise<RuntimeResult> {
    return this.instance.setRoute(route);
  }

  removeRoute(routeId: string): RuntimeResult {
    return this.instance.removeRoute(routeId);
  }

  listRoutes(): RuntimeResult[] {
    return this.instance.listRoutes();
  }

  rotateRoute(routeId: string): Promise<RuntimeResult | null> {
    return this.instance.rotateRoute(routeId);
  }

  locations(provider?: string): Promise<RuntimeResult> {
    return this.instance.locations(provider);
  }

  refreshLocations(provider?: string): Promise<RuntimeResult> {
    return this.instance.refreshLocations(provider);
  }

  providerStatus(): RuntimeResult {
    return this.instance.providerStatus();
  }

  egressInventory(): RuntimeResult {
    return this.instance.egressInventory();
  }

  blockEgressIp(ip: string): RuntimeResult {
    return this.instance.blockEgressIp(ip);
  }

  releaseEgressIp(ip: string): RuntimeResult {
    return this.instance.releaseEgressIp(ip);
  }

  getPolicy(): ProxyRuntimePolicy {
    return this.instance.getPolicy();
  }

  setPolicy(policy: ProxyRuntimePolicy): ProxyRuntimePolicy {
    return this.instance.setPolicy(policy);
  }

  getLimits(): RuntimeResult {
    return this.instance.getLimits();
  }

  patchLimits(patch: RuntimeResult): RuntimeResult {
    return this.instance.patchLimits(patch);
  }

  setLimitProfile(name: string, limits: RuntimeResult): RuntimeResult {
    return this.instance.setLimitProfile(name, limits);
  }

  patchLimitProfile(name: string, patch: RuntimeResult): RuntimeResult {
    return this.instance.patchLimitProfile(name, patch);
  }

  limitProfile(name: string): RuntimeResult | null {
    return this.instance.limitProfile(name);
  }

  listLimitProfiles(): RuntimeResult[] {
    return this.instance.listLimitProfiles();
  }

  setAuthTokenHandler(handler?: WispAuthTokenHandler): RuntimeResult {
    return this.instance.setAuthTokenHandler(
      handler
        ? async (token) => normalizeAuthHandlerResult(await handler(token))
        : undefined,
    );
  }

  registerAuthToken(token: string, policy: WispAuthTokenPolicy): RuntimeResult {
    return this.instance.registerAuthToken(token, policy);
  }

  revokeAuthToken(token: string): RuntimeResult {
    return this.instance.revokeAuthToken(token);
  }

  listAuthTokens(): RuntimeResult[] {
    return this.instance.listAuthTokens();
  }

  authTokenPolicy(token: string): WispAuthTokenPolicy | null {
    return this.instance.authTokenPolicy(token);
  }
}

export function createWispRustRuntime(
  options: WispRustRuntimeOptions = {},
): WispRustRuntime {
  return new WispRustRuntime(options);
}

export type WispRustBunProxyOptions = WispRustRuntimeOptions & {
  appTarget: string;
  appTargets?: Record<string, string>;
  proxyPath?: string;
  /** Resolve the public mount for each request, or return null to disable it */
  resolveProxyPath?: (request: Request) => string | null | Promise<string | null>;
  hostname?: string;
  port?: number;
  idleTimeout?: number;
  trustedBunFront?: boolean;
  stopOnSignals?: boolean;
  /** Most WebSockets held at once, WISP_FRONT_MAX_WEBSOCKETS or 2048 */
  maxWebSockets?: number;
  /** Most WebSockets held for one client address, WISP_FRONT_MAX_WEBSOCKETS_PER_IP or 128 */
  maxWebSocketsPerIp?: number;
  /** Most bytes held for one WebSocket that is not draining, WISP_FRONT_MAX_BUFFERED_BYTES or 4 MiB */
  maxBufferedBytes?: number;
  /** Replaces Cloudflare's ranges as the peers whose CF-Connecting-IP is believed */
  trustedEdgeCidrs?: string[];
  /** Runs before the upstream connect; return false to refuse the upgrade with 403 */
  checkOrigin?: (
    origin: string | null,
    request: Request,
  ) => boolean | Promise<boolean>;
};

type BunProxyMessage = string | Buffer;
type BunProxySocketData = {
  upstream: WebSocket;
  slot: WebSocketSlot;
  downstream?: Bun.ServerWebSocket<BunProxySocketData>;
  /** Upstream frames that arrived before the client socket opened */
  queued: BunProxyMessage[];
  queuedBytes: number;
  maxBufferedBytes: number;
  closed: boolean;
  closeInfo?: { code: number; reason: string };
};

export type WispRustBunProxy = {
  runtime: WispRustRuntime;
  server: Bun.Server<BunProxySocketData>;
  stop(): Promise<RuntimeStatus>;
};

export async function serveWispRustBunProxy(
  options: WispRustBunProxyOptions,
): Promise<WispRustBunProxy> {
  if (!process.versions.bun) {
    throw new Error("serveWispRustBunProxy requires Bun");
  }
  const runtime = createWispRustRuntime({
    ...options,
    trustedBunFront: options.trustedBunFront ?? true,
  });
  await runtime.start();
  const context = runtime.proxyContext(options.proxyPath);
  const appTarget = new URL(options.appTarget);
  const appTargets = new Map(
    Object.entries(options.appTargets ?? {}).map(([hostname, target]) => [
      hostname.toLowerCase(),
      new URL(target),
    ]),
  );
  const edgeTrust = createEdgeTrust(options.trustedEdgeCidrs);
  const limiter = new WebSocketLimiter(
    options.maxWebSockets ??
      positiveIntegerEnv("WISP_FRONT_MAX_WEBSOCKETS", DEFAULT_MAX_WEBSOCKETS),
    options.maxWebSocketsPerIp ??
      positiveIntegerEnv(
        "WISP_FRONT_MAX_WEBSOCKETS_PER_IP",
        DEFAULT_MAX_WEBSOCKETS_PER_IP,
      ),
  );
  const maxBufferedBytes =
    options.maxBufferedBytes ??
    positiveIntegerEnv(
      "WISP_FRONT_MAX_BUFFERED_BYTES",
      DEFAULT_MAX_BUFFERED_BYTES,
    );

  const handleRequest = async (
    request: Request,
    activeServer: Bun.Server<BunProxySocketData>,
  ): Promise<Response | undefined> => {
    const requestUrl = new URL(request.url);
    // Upstream URLs are built from a fixed origin, and a path that names an authority is
    // never a request for this app
    if (isAuthorityPath(requestUrl.pathname)) {
      return new Response("Invalid request path", { status: 400 });
    }
    const peer = activeServer.requestIP(request)?.address;
    const clientIp = resolveCanonicalClientIp(edgeTrust, peer, request.headers);
    if (!clientIp) {
      return new Response("Client address unavailable", { status: 400 });
    }
    const selectedAppTarget =
      appTargets.get(requestUrl.hostname.toLowerCase()) ?? appTarget;
    if (request.headers.get("upgrade")?.toLowerCase() === "websocket") {
      const mount = options.resolveProxyPath
        ? await options.resolveProxyPath(request)
        : context.proxyPath;
      const connectionContext = mount === null
        ? null
        : { ...context, proxyPath: normalizeMountPath(mount) };
      const toWisp =
        connectionContext !== null &&
        pathMatchesMount(requestUrl.pathname, connectionContext.proxyPath);
      return openProxiedWebSocket({
        request,
        server: activeServer,
        upstreamUrl:
          toWisp && connectionContext
            ? wispWebSocketUrl(requestUrl, connectionContext)
            : appWebSocketUrl(requestUrl, selectedAppTarget),
        target: toWisp ? context.boundUrl : selectedAppTarget,
        clientIp,
        // The secret is for the native listener only, never for the app
        edgeSecret: toWisp ? runtime.edgeSecret : undefined,
        limiter,
        maxBufferedBytes,
        checkOrigin: options.checkOrigin,
      });
    }
    return proxyBunHttpRequest(request, requestUrl, selectedAppTarget, {
      clientIp,
      trustedPeer: isTrustedEdgePeer(edgeTrust, peer),
    });
  };

  const server = Bun.serve<BunProxySocketData>({
    hostname: options.hostname ?? "127.0.0.1",
    port: options.port ?? 8081,
    idleTimeout: options.idleTimeout ?? 255,
    async fetch(request, activeServer) {
      try {
        return await handleRequest(request, activeServer);
      } catch (error) {
        if (error instanceof ProxyRejection) {
          return new Response(error.message, { status: error.status });
        }
        console.error("wisp-rust-vite: proxy request failed", error);
        return new Response("Bad gateway", { status: 502 });
      }
    },
    websocket: {
      // Bun holds at most this much for a client that has stopped reading, and drops the rest
      backpressureLimit: maxBufferedBytes,
      open(socket) {
        const data = socket.data;
        data.downstream = socket;
        if (data.closed) {
          const info = data.closeInfo ?? { code: 1011, reason: "" };
          socket.close(info.code, info.reason);
          return;
        }
        const queued = data.queued.splice(0);
        data.queuedBytes = 0;
        for (const message of queued) relayToClient(data, message);
      },
      message(socket, message) {
        const data = socket.data;
        if (data.closed) return;
        const upstream = data.upstream;
        if (upstream.readyState !== WebSocket.OPEN) {
          shutdownProxySocket(data, 1011, "Upstream WebSocket is not open", "local");
          return;
        }
        if (
          upstream.bufferedAmount + bunProxyMessageBytes(message) >
          data.maxBufferedBytes
        ) {
          shutdownProxySocket(
            data,
            1009,
            "Upstream WebSocket is not reading fast enough",
            "local",
          );
          return;
        }
        try {
          upstream.send(message);
        } catch {
          shutdownProxySocket(data, 1011, "Upstream WebSocket failed", "local");
        }
      },
      close(socket, code, reason) {
        shutdownProxySocket(socket.data, code, reason, "downstream");
      },
    },
  });

  let stopPromise: Promise<RuntimeStatus> | undefined;
  const stop = () => {
    if (!stopPromise) {
      stopPromise = server.stop(true).then(() => runtime.stop());
    }
    return stopPromise;
  };
  if (options.stopOnSignals ?? true) {
    const stopForSignal = () => {
      stop().then(
        () => process.exit(0),
        (error) => {
          console.error(error);
          process.exit(1);
        },
      );
    };
    process.once("SIGINT", stopForSignal);
    process.once("SIGTERM", stopForSignal);
  }
  return { runtime, server, stop };
}

function pathMatchesMount(pathname: string, mountPath: string): boolean {
  const normalized = normalizeMountPath(mountPath);
  if (normalized === "/") return pathname.startsWith("/");
  return pathname === normalized || pathname.startsWith(normalized + "/");
}

function bunProxyMessageBytes(message: BunProxyMessage): number {
  return typeof message === "string"
    ? Buffer.byteLength(message)
    : message.byteLength;
}

function wispWebSocketUrl(
  requestUrl: URL,
  context: WispRustProxyContext,
): URL {
  return buildUpstreamUrl(
    context.boundUrl,
    rewriteMountPath(
      requestUrl.pathname,
      context.proxyPath,
      context.endpointPath,
    ),
    requestUrl.search,
    "ws",
  );
}

function appWebSocketUrl(requestUrl: URL, appTarget: URL): URL {
  return buildUpstreamUrl(
    appTarget,
    requestUrl.pathname,
    requestUrl.search,
    "ws",
  );
}

/** Ends both halves of a proxied WebSocket once, releasing its connection slot */
function shutdownProxySocket(
  data: BunProxySocketData,
  code: number,
  reason: string | undefined,
  from: "downstream" | "upstream" | "local",
) {
  if (data.closed) return;
  data.closed = true;
  data.slot.release();
  data.queued.length = 0;
  data.queuedBytes = 0;
  const closeCode = forwardableCloseCode(code);
  const closeReason = truncateCloseReason(reason);
  data.closeInfo = { code: closeCode, reason: closeReason };
  if (from !== "downstream" && data.downstream) {
    try {
      data.downstream.close(closeCode, closeReason);
    } catch {
      // The client socket is already gone
    }
  }
  if (from !== "upstream") closeUpstreamSocket(data.upstream, closeCode, closeReason);
}

function closeUpstreamSocket(upstream: WebSocket, code: number, reason: string) {
  if (upstream.readyState >= WebSocket.CLOSING) return;
  try {
    upstream.close(code, reason);
  } catch {
    // A code the client API refuses to send still has to end the connection
    try {
      upstream.close();
    } catch {
      // Already closed
    }
  }
}

/** Sends one upstream frame to the client, holding it until the client socket has opened */
function relayToClient(data: BunProxySocketData, payload: BunProxyMessage) {
  if (data.closed) return;
  const socket = data.downstream;
  if (!socket) {
    const bytes = bunProxyMessageBytes(payload);
    if (data.queuedBytes + bytes > data.maxBufferedBytes) {
      shutdownProxySocket(data, 1009, "Queue limit exceeded", "local");
      return;
    }
    data.queued.push(payload);
    data.queuedBytes += bytes;
    return;
  }
  // 0 means Bun dropped the frame, and a deep buffer means the client is not reading
  if (
    socket.send(payload) === 0 ||
    socket.getBufferedAmount() > data.maxBufferedBytes
  ) {
    shutdownProxySocket(
      data,
      1009,
      "Client is not reading fast enough",
      "local",
    );
  }
}

/**
 * Connects the upstream socket first and only then accepts the client's upgrade, so a refusal
 * reaches the client as the same HTTP status and the subprotocol is the one upstream chose.
 */
async function openProxiedWebSocket(input: {
  request: Request;
  server: Bun.Server<BunProxySocketData>;
  upstreamUrl: URL;
  target: URL;
  clientIp: string;
  edgeSecret?: string;
  limiter: WebSocketLimiter;
  maxBufferedBytes: number;
  checkOrigin?: WispRustBunProxyOptions["checkOrigin"];
}): Promise<Response | undefined> {
  const { request, upstreamUrl } = input;
  const slot = input.limiter.acquire(input.clientIp);
  if (typeof slot === "string") {
    return new Response(
      slot === "total"
        ? "Too many connections"
        : "Too many connections from this address",
      {
        status: slot === "total" ? 503 : 429,
        headers: { "retry-after": "5", "cache-control": "private, no-store" },
      },
    );
  }
  let upstream: WebSocket | undefined;
  let handedOff = false;
  try {
    const origin = request.headers.get("origin");
    if (input.checkOrigin && !(await input.checkOrigin(origin, request))) {
      return new Response("Origin not allowed", { status: 403 });
    }
    const protocols = (request.headers.get("sec-websocket-protocol") ?? "")
      .split(",")
      .map((protocol) => protocol.trim())
      .filter(Boolean);
    const headers = buildUpstreamSocketHeaders({
      origin,
      clientIp: input.clientIp,
      edgeSecret: input.edgeSecret,
    });
    // Rechecked here because this is the last step before the connection is made
    assertSameOrigin(upstreamUrl, input.target, "ws");
    const socket = new WebSocket(upstreamUrl.href, { headers, protocols });
    upstream = socket;
    socket.binaryType = "arraybuffer";
    const data: BunProxySocketData = {
      upstream: socket,
      slot,
      queued: [],
      queuedBytes: 0,
      maxBufferedBytes: input.maxBufferedBytes,
      closed: false,
    };
    socket.addEventListener("message", (event) => {
      relayToClient(
        data,
        typeof event.data === "string"
          ? event.data
          : Buffer.from(event.data as ArrayBuffer),
      );
    });
    socket.addEventListener("close", (event) => {
      shutdownProxySocket(data, event.code, event.reason, "upstream");
    });
    socket.addEventListener("error", () => {
      shutdownProxySocket(data, 1011, "Upstream WebSocket failed", "upstream");
    });
    const outcome = await new Promise<"open" | "failed" | "timeout" | "aborted">(
      (resolveOutcome) => {
        const finish = (result: "open" | "failed" | "timeout" | "aborted") => {
          clearTimeout(timer);
          request.signal.removeEventListener("abort", onAbort);
          resolveOutcome(result);
        };
        const onAbort = () => finish("aborted");
        const timer = setTimeout(
          () => finish("timeout"),
          BUN_UPSTREAM_CONNECT_TIMEOUT_MS,
        );
        socket.addEventListener("open", () => finish("open"), { once: true });
        socket.addEventListener("error", () => finish("failed"), { once: true });
        socket.addEventListener("close", () => finish("failed"), { once: true });
        request.signal.addEventListener("abort", onAbort, { once: true });
      },
    );
    if (outcome === "timeout") {
      return new Response("Upstream WebSocket connection timed out", {
        status: 504,
      });
    }
    if (outcome === "aborted") return new Response(null, { status: 499 });
    if (outcome === "failed" || data.closed) {
      const status = mirroredRejectionStatus(
        await probeUpstreamStatus(upstreamUrl, { headers, protocols }),
      );
      return new Response("WebSocket upstream refused the connection", {
        status,
        headers: { "cache-control": "private, no-store" },
      });
    }
    const selected = socket.protocol;
    const upgraded = input.server.upgrade(request, {
      data,
      headers: selected ? { "Sec-WebSocket-Protocol": selected } : undefined,
    });
    if (!upgraded) {
      return new Response("WebSocket upgrade failed", { status: 500 });
    }
    handedOff = true;
    return undefined;
  } finally {
    if (!handedOff) {
      slot.release();
      if (upstream) closeUpstreamSocket(upstream, 1000, "");
    }
  }
}

async function proxyBunHttpRequest(
  request: Request,
  requestUrl: URL,
  appTarget: URL,
  identity: { clientIp: string; trustedPeer: boolean },
): Promise<Response> {
  const upstream = buildUpstreamUrl(
    appTarget,
    requestUrl.pathname,
    requestUrl.search,
  );
  const headers = buildUpstreamRequestHeaders(request.headers, {
    clientIp: identity.clientIp,
    trustedPeer: identity.trustedPeer,
    publicHost: requestUrl.host,
    publicProtocol: requestUrl.protocol,
  });
  assertSameOrigin(upstream, appTarget);
  const hasBody = request.method !== "GET" && request.method !== "HEAD";
  let response: Response;
  try {
    response = await fetch(upstream, {
      method: request.method,
      headers,
      body: hasBody ? request.body : undefined,
      redirect: "manual",
      // The body is relayed as the app encoded it, so Content-Encoding stays true
      decompress: false,
      signal: request.signal,
    });
  } catch {
    return new Response("Bad gateway", { status: 502 });
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: filterUpstreamResponseHeaders(response.headers),
  });
}

export function wispRustVite(options: WispRustViteOptions = {}): Plugin {
  const runtimeOptions = defaultViteRuntimeOptions(options);
  let runtime: WispRustRuntime | undefined;
  let closeRegistered = false;
  let proxyConfig: { path: string; options: ProxyOptions } | undefined;
  let resolvedWsPort: number | undefined;

  const getRuntime = (root: string): WispRustRuntime => {
    if (!runtime) {
      runtime = createWispRustRuntime({
        ...runtimeOptions,
        cwd: runtimeOptions.cwd ?? root,
        resolvedWsPort,
      });
    }
    return runtime;
  };

  const getProxyConfig = (
    root: string,
  ): { path: string; options: ProxyOptions } => {
    if (!proxyConfig) {
      proxyConfig = getRuntime(root).viteProxyOptions(runtimeOptions);
    }
    return proxyConfig;
  };

  const setupServer = async (
    httpServer: ClosableServer | null | undefined,
    root: string,
  ) => {
    const activeRuntime = getRuntime(root);
    const shouldStart = runtimeOptions.autoStart ?? true;
    if (shouldStart) {
      await activeRuntime.start();
    }
    if (
      (runtimeOptions.stopOnClose ?? true) &&
      httpServer &&
      !closeRegistered
    ) {
      closeRegistered = true;
      httpServer.once("close", () => {
        return activeRuntime.stop().catch(() => undefined);
      });
    }
  };

  const setupBunProxy = (
    httpServer: UpgradeServer | null | undefined,
    root: string,
  ) => {
    if (!process.versions.bun || !httpServer) return;
    const context = getRuntime(root).proxyContext(runtimeOptions.proxyPath);
    httpServer.prependListener("upgrade", (request, socket, head) => {
      proxyBunWebSocketUpgrade(request, socket, head, context);
    });
  };

  const setupBunMiddlewareProxy = (
    middlewares: BunMiddlewareStack,
    root: string,
  ) => {
    if (!process.versions.bun) return;
    const context = getRuntime(root).proxyContext(runtimeOptions.proxyPath);
    middlewares.use((request, response, next) => {
      proxyBunAdapterWebSocketUpgrade(request, response, next, context);
    });
  };

  return {
    name: "wisp-rust-vite",
    enforce: "pre",
    async config(config): Promise<UserConfig> {
      const root = resolve(config.root ?? process.cwd());
      resolvedWsPort =
        runtimeOptions.resolvedWsPort ??
        (await resolveFreeWsPort({
          ...runtimeOptions,
          cwd: runtimeOptions.cwd ?? root,
        }));
      const proxy = getProxyConfig(root);
      if (process.versions.bun) return {};
      return {
        server: {
          proxy: {
            [proxy.path]: proxy.options,
          },
        },
        preview: {
          proxy: {
            [proxy.path]: proxy.options,
          },
        },
      };
    },
    async configureServer(server) {
      await setupServer(server.httpServer, server.config.root);
      setupBunMiddlewareProxy(server.middlewares, server.config.root);
      setupBunProxy(server.httpServer, server.config.root);
    },
    async configurePreviewServer(server) {
      if (runtimeOptions.startInPreview ?? true) {
        await setupServer(server.httpServer, server.config.root);
        setupBunProxy(server.httpServer, server.config.root);
      }
    },
  };
}

function proxyBunAdapterWebSocketUpgrade(
  request: IncomingMessage,
  response: ServerResponse,
  next: () => unknown,
  context: WispRustProxyContext,
) {
  const requestUrl = request.url ?? "/";
  const pathname = new URL(requestUrl, "http://wisp.invalid").pathname;
  if (
    request.headers.upgrade?.toLowerCase() !== "websocket" ||
    !pathMatchesMount(pathname, context.proxyPath)
  ) {
    next();
    return;
  }

  const bunRequestSymbol = Symbol.for("::adapter-bun::request::");
  const bunResponseSymbol = Symbol.for("::adapter-bun::response::");
  const bunServerSymbol = Symbol.for("@eslym/sveltekit-adapter-bun/server");
  const originalRequest = (request as unknown as Record<symbol, unknown>)[
    bunRequestSymbol
  ];
  const finishResponse = (response as unknown as Record<symbol, unknown>)[
    bunResponseSymbol
  ];
  const bunServer = (globalThis as Record<symbol, unknown>)[bunServerSymbol];
  if (
    !(originalRequest instanceof Request) ||
    typeof finishResponse !== "function" ||
    !isBunUpgradeApi(bunServer)
  ) {
    next();
    return;
  }

  const originalUrl = new URL(originalRequest.url);
  if (isAuthorityPath(originalUrl.pathname)) {
    next();
    return;
  }
  const target = wispWebSocketUrl(originalUrl, context).href;
  const protocols = (originalRequest.headers.get("sec-websocket-protocol") ?? "")
    .split(",")
    .map((protocol) => protocol.trim())
    .filter(Boolean);
  const upgraded = bunServer.upgrade(originalRequest, {
    data: createBunProxySocketData(
      target,
      originalRequest.headers.get("origin"),
      protocols,
      canonicalIp(bunServer.requestIP?.(originalRequest)?.address) ?? undefined,
      context.edgeSecret,
    ),
  });
  if (!upgraded) {
    next();
    return;
  }
  finishResponse(undefined);
}

function isBunUpgradeApi(value: unknown): value is BunUpgradeApi {
  return Boolean(value && typeof value === "object" && "upgrade" in value);
}

function createBunProxySocketData(
  target: string,
  origin: string | null,
  protocols: string[],
  clientIp: string | undefined,
  edgeSecret: string | undefined,
): BunAdapterProxySocketData {
  let downstream: BunProxySocket | undefined;
  let upstream: WebSocket | undefined;
  let closed = false;
  const pending: Array<string | Buffer> = [];
  let pendingBytes = 0;
  let connectTimer: ReturnType<typeof setTimeout> | undefined;

  const closeDownstream = (code: number, reason: string) => {
    if (closed) return;
    closed = true;
    downstream?.close(forwardableCloseCode(code), truncateCloseReason(reason));
  };

  return {
    open(socket) {
      downstream = socket;
      // Trusted_edge listeners need the front's identity on every upgrade
      const headers =
        edgeSecret && clientIp
          ? buildUpstreamSocketHeaders({ origin, clientIp, edgeSecret })
          : origin
            ? { Origin: origin }
            : undefined;
      upstream = new WebSocket(target, {
        headers,
        protocols,
      });
      upstream.binaryType = "arraybuffer";
      connectTimer = setTimeout(() => {
        pending.length = 0;
        pendingBytes = 0;
        closeDownstream(1013, "Wisp upstream connection timed out");
        upstream?.close();
      }, BUN_UPSTREAM_CONNECT_TIMEOUT_MS);
      upstream.addEventListener("open", () => {
        clearTimeout(connectTimer);
        connectTimer = undefined;
        for (const message of pending.splice(0)) upstream?.send(message);
        pendingBytes = 0;
      });
      upstream.addEventListener("message", (event) => {
        const result = downstream?.send(
          typeof event.data === "string"
            ? event.data
            : Buffer.from(event.data as ArrayBuffer),
        );
        // 0 means Bun dropped the frame because the client is not reading
        if (result === 0) {
          closeDownstream(1009, "Client is not reading fast enough");
          upstream?.close();
        }
      });
      upstream.addEventListener("error", () => {
        clearTimeout(connectTimer);
        connectTimer = undefined;
        closeDownstream(1011, "Wisp upstream connection failed");
      });
      upstream.addEventListener("close", (event) => {
        clearTimeout(connectTimer);
        connectTimer = undefined;
        closeDownstream(event.code, event.reason);
      });
    },
    message(_socket, message) {
      if (upstream?.readyState === WebSocket.OPEN) {
        if (
          upstream.bufferedAmount + bunProxyMessageBytes(message) >
          DEFAULT_MAX_BUFFERED_BYTES
        ) {
          closeDownstream(1009, "Wisp upstream is not reading fast enough");
          upstream.close();
          return;
        }
        upstream.send(message);
        return;
      }
      const messageBytes = bunProxyMessageBytes(message);
      if (pendingBytes + messageBytes > MAX_BUN_PENDING_BYTES) {
        pending.length = 0;
        pendingBytes = 0;
        closeDownstream(1009, "Wisp upstream queue limit exceeded");
        upstream?.close();
        return;
      }
      pending.push(message);
      pendingBytes += messageBytes;
    },
    close(_socket, code, reason) {
      if (closed) return;
      closed = true;
      clearTimeout(connectTimer);
      connectTimer = undefined;
      pending.length = 0;
      pendingBytes = 0;
      if (upstream && upstream.readyState < WebSocket.CLOSING) {
        closeUpstreamSocket(
          upstream,
          forwardableCloseCode(code),
          truncateCloseReason(reason),
        );
      }
    },
  };
}

function defaultViteRuntimeOptions(
  options: WispRustViteOptions,
): WispRustViteOptions {
  if (options.tomlPath || options.toml || options.config) {
    return options;
  }
  return {
    ...options,
    toml: DEFAULT_WISP_RUST_VITE_TOML,
    source: "wisp-rust-vite:default",
  };
}

function proxyBunWebSocketUpgrade(
  request: IncomingMessage,
  socket: Duplex,
  head: Buffer,
  context: WispRustProxyContext,
) {
  const requestUrl = request.url ?? "/";
  const pathname = new URL(requestUrl, "http://wisp.invalid").pathname;
  const proxyPath = normalizeMountPath(context.proxyPath);
  if (
    request.headers.upgrade?.toLowerCase() !== "websocket" ||
    !pathMatchesMount(pathname, proxyPath)
  ) {
    return;
  }
  const upstreamUrl = context.boundUrl;
  const upstreamPort = Number.parseInt(
    upstreamUrl.port || (upstreamUrl.protocol === "wss:" ? "443" : "80"),
    10,
  );
  const rewrittenUrl = rewriteMountPath(
    requestUrl,
    context.proxyPath,
    context.endpointPath,
  );
  socket.pause();

  const onConnected = function (this: Duplex) {
    const requestLine = `${request.method ?? "GET"} ${rewrittenUrl} HTTP/${request.httpVersion}`;
    const headers: string[] = [requestLine, `Host: ${upstreamUrl.host}`];
    for (let index = 0; index < request.rawHeaders.length; index += 2) {
      const name = request.rawHeaders[index];
      const value = request.rawHeaders[index + 1];
      if (!name || value === undefined) continue;
      // Identity headers are the front's to write, never the client's
      if (UPSTREAM_IDENTITY_HEADERS.has(name.toLowerCase())) continue;
      headers.push(`${name}: ${value}`);
    }
    const peerIp = canonicalIp(request.socket.remoteAddress);
    if (context.edgeSecret && peerIp) {
      headers.push(
        `X-Forwarded-For: ${peerIp}`,
        `CF-Connecting-IP: ${peerIp}`,
        `${EDGE_SECRET_HEADER}: ${context.edgeSecret}`,
      );
    }
    this.write(`${headers.join("\r\n")}\r\n\r\n`);
    if (head.length > 0) this.write(head);
    socket.pipe(this).pipe(socket);
    socket.resume();
  };

  const upstream =
    upstreamUrl.protocol === "wss:"
      ? connectTls({
          host: upstreamUrl.hostname,
          port: upstreamPort,
          servername: upstreamUrl.hostname,
        })
      : connectTcp({ host: upstreamUrl.hostname, port: upstreamPort });
  let connectTimedOut = false;
  const connectTimer = setTimeout(() => {
    connectTimedOut = true;
    upstream.destroy();
    socket.end("HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n");
  }, BUN_UPSTREAM_CONNECT_TIMEOUT_MS);
  upstream.once("connect", onConnected);
  upstream.once("error", () => {
    clearTimeout(connectTimer);
    if (!connectTimedOut) {
      socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
    }
  });
  upstream.once("connect", () => clearTimeout(connectTimer));
  socket.once("error", () => upstream.destroy());
  socket.once("close", () => upstream.destroy());
  upstream.once("close", () => socket.end());
}

/** Headers a client must not supply to the native listener, which trusts them in trusted_edge mode */
const UPSTREAM_IDENTITY_HEADERS = new Set([
  "host",
  "x-forwarded-for",
  "x-real-ip",
  "forwarded",
  "true-client-ip",
  "cf-connecting-ip",
  EDGE_SECRET_HEADER,
]);

export const wispRustPlugin = wispRustVite;

function loadNative(): WispRustNativeModule {
  const explicitPath = process.env.WISP_RUST_NAPI_PATH?.trim();
  const workspaceRoot = process.env.ST_WORKSPACE_ROOT?.trim();
  const candidates = [
    explicitPath,
    workspaceRoot
      ? resolve(workspaceRoot, "wisp-rust/crates/wisp-rust-napi/index.js")
      : undefined,
  ].filter((path): path is string => Boolean(path));
  for (const candidate of candidates) {
    const path =
      candidate.endsWith(".js") || candidate.endsWith(".node")
        ? candidate
        : resolve(candidate, "index.js");
    if (existsSync(path)) {
      const native = require(path) as WispRustNativeModule;
      if (native.WispRust) return native;
    }
  }
  return require("wisp-rust-napi/index.js") as WispRustNativeModule;
}

function isPortFree(port: number, host: string): Promise<boolean> {
  return new Promise((resolveFree) => {
    const tester = createServer();
    tester.once("error", () => resolveFree(false));
    tester.once("listening", () => {
      tester.close(() => resolveFree(true));
    });
    tester.listen(port, host);
  });
}

async function findFreePort(
  host: string,
  startPort: number,
  maxAttempts = 100,
): Promise<number> {
  let candidate = startPort;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    if (await isPortFree(candidate, host)) return candidate;
    candidate += 1;
  }
  throw new Error(
    `No free port found on ${host} after ${maxAttempts} attempts from ${startPort}`,
  );
}

async function resolveFreeWsPort(
  options: WispRustRuntimeOptions,
): Promise<number | undefined> {
  const ws = recordField(buildRuntimeTomlTable(options), "wisp_websocket");
  if (!ws || ws.enabled === false) return undefined;
  const host = typeof ws.host === "string" ? ws.host : "127.0.0.1";
  const basePort = typeof ws.port === "number" ? ws.port : 4142;
  return findFreePort(host, basePort);
}

function createNativeRuntime(
  native: WispRustNativeModule,
  options: WispRustRuntimeOptions,
): WispRust {
  if (options.proxyConfigPath || options.authenticatedProxyConfigPath || options.trustedBunFront) {
    return native.WispRust.fromToml(
      mergedRuntimeToml(options),
      options.source ??
        options.tomlPath ??
        options.proxyConfigPath ??
        options.authenticatedProxyConfigPath,
    );
  }
  if (options.tomlPath) {
    if (options.resolvedWsPort !== undefined) {
      const table = parseRuntimeToml(
        readFileSync(resolvePath(options.tomlPath, options.cwd), "utf-8"),
        options.tomlPath,
      );
      applyWsPortOverride(table, options.resolvedWsPort);
      return native.WispRust.fromToml(stringifyToml(table), options.tomlPath);
    }
    return native.WispRust.fromTomlPath(
      resolvePath(options.tomlPath, options.cwd),
    );
  }
  if (options.toml) {
    if (options.resolvedWsPort !== undefined) {
      const table = parseRuntimeToml(options.toml, options.source);
      applyWsPortOverride(table, options.resolvedWsPort);
      return native.WispRust.fromToml(stringifyToml(table), options.source);
    }
    return native.WispRust.fromToml(options.toml, options.source);
  }
  if (options.config) {
    return native.WispRust.fromConfig({
      config: options.config,
      logLevel: options.logLevel,
    });
  }
  if (options.logLevel !== undefined) {
    return native.WispRust.fromConfig({
      config: {},
      logLevel: options.logLevel,
    });
  }
  return native.WispRust.fromConfig({
    config: {},
  });
}

function resolvePath(path: string, cwd = process.cwd()): string {
  return path.startsWith("/") ? path : resolve(cwd, path);
}

function buildRuntimeTomlTable(options: WispRustRuntimeOptions): TomlTable {
  const base = parseRuntimeToml(
    baseRuntimeToml(options),
    options.source ?? options.tomlPath,
  );
  if (options.proxyConfigPath) {
    mergeTomlTables(
      base,
      proxyConfigTable(resolvePath(options.proxyConfigPath, options.cwd)),
    );
  }
  if (options.authenticatedProxyConfigPath) {
    mergeTomlTables(
      base,
      proxyConfigTable(
        resolvePath(options.authenticatedProxyConfigPath, options.cwd),
      ),
    );
  }
  if (options.trustedBunFront) {
    applyTrustedBunFront(base, options.trustedEdgeSecret);
  }
  return base;
}

function applyTrustedBunFront(table: TomlTable, edgeSecret?: string) {
  const record = table as TomlRecord;
  const ws = isRecord(record.wisp_websocket) ? record.wisp_websocket : {};
  ws.host = "127.0.0.1";
  delete ws.bind_addr;
  ws.ingress_mode = "trusted_edge";
  // The native listener refuses upgrades that do not carry this in x-wisp-edge-secret
  if (edgeSecret) ws.trusted_edge_secret = edgeSecret;
  record.wisp_websocket = ws;

  const wisp = isRecord(record.wisp) ? record.wisp : {};
  const client = isRecord(wisp.client) ? wisp.client : {};
  client.parse_real_ip = true;
  // Operator-supplied peers stay trusted, loopback is added to them
  const configured = client.parse_real_ip_from;
  const operatorPeers = (
    Array.isArray(configured)
      ? configured
      : typeof configured === "string"
        ? [configured]
        : []
  ).filter((entry): entry is string => typeof entry === "string");
  client.parse_real_ip_from = [
    ...new Set([...operatorPeers, "127.0.0.1", "::1"]),
  ];
  wisp.client = client;
  record.wisp = wisp;
}

function mergedRuntimeToml(options: WispRustRuntimeOptions): string {
  const base = buildRuntimeTomlTable(options);
  applyWsPortOverride(base, options.resolvedWsPort);
  return stringifyToml(base);
}

function applyWsPortOverride(table: TomlTable, port: number | undefined) {
  if (port === undefined) return;
  const record = table as TomlRecord;
  const ws = isRecord(record.wisp_websocket) ? record.wisp_websocket : {};
  ws.port = port;
  record.wisp_websocket = ws;
}

function baseRuntimeToml(options: WispRustRuntimeOptions): string {
  if (options.tomlPath) {
    return readFileSync(resolvePath(options.tomlPath, options.cwd), "utf-8");
  }
  if (options.toml) {
    return options.toml;
  }
  if (options.config || options.logLevel !== undefined) {
    throw new Error("proxyConfigPath requires tomlPath or toml");
  }
  return "";
}

function configureAuthenticatedProfile(
  instance: WispRust,
  options: WispRustRuntimeOptions,
) {
  const handler = options.authTokenHandler;
  const multiplier = options.authenticatedLimitMultiplier;
  const profileName =
    options.authenticatedProfileName ?? DEFAULT_AUTHENTICATED_PROFILE;
  const hasAuthenticatedProviderPolicy =
    Boolean(options.authenticatedProxyConfigPath) ||
    Boolean(options.authenticatedAllowedProxyProviders);
  if (multiplier !== undefined) {
    const normalizedMultiplier = Number.isFinite(multiplier)
      ? Math.max(1, Math.floor(multiplier))
      : 1;
    const baseLimits = instance.getLimits();
    const authenticatedLimits = multiplyWispLimits(
      baseLimits,
      normalizedMultiplier,
    );
    instance.setLimitProfile(profileName, authenticatedLimits);
  }
  if (handler) {
    instance.setAuthTokenHandler(async (token) => {
      const policy = normalizeAuthHandlerResult(await handler(token));
      if (!policy) return null;
      if (multiplier === undefined && !hasAuthenticatedProviderPolicy)
        return policy;
      return {
        ...(multiplier === undefined ? {} : { limitProfile: profileName }),
        allowedProxyProviders:
          options.authenticatedAllowedProxyProviders ??
          DEFAULT_AUTHENTICATED_PROVIDERS,
        ...policy,
      };
    });
  }
}

function normalizeAuthHandlerResult(
  result: WispAuthTokenHandlerResult,
): WispAuthTokenPolicy | null {
  if (result === true) return {};
  if (!result) return null;
  return result;
}

function multiplyWispLimits(
  limits: RuntimeResult,
  multiplier: number,
): RuntimeResult {
  const out = JSON.parse(JSON.stringify(limits)) as RuntimeResult;
  for (const key of MULTIPLIED_LIMIT_FIELDS) {
    const val = out[key];
    if (typeof val === "number" && Number.isFinite(val) && val > 0) {
      out[key] = Math.min(
        Number.MAX_SAFE_INTEGER,
        Math.floor(val * multiplier),
      );
    }
  }
  return out;
}

function parseRuntimeToml(toml: string, source = "wisp-rust-vite"): TomlTable {
  if (!toml.trim()) {
    return {};
  }
  const parsed = parseToml(toml);
  if (!isRecord(parsed)) {
    throw new Error(`Invalid Wisp Rust TOML config: ${source}`);
  }
  return parsed;
}

function mergeTomlTables(target: TomlTable, source: TomlTable): TomlTable {
  for (const [key, val] of Object.entries(source)) {
    const current = target[key];
    if (isRecord(current) && isRecord(val)) {
      target[key] = mergeTomlTables(current, val);
    } else {
      target[key] = val;
    }
  }
  return target;
}

function proxyConfigTable(path: string): TomlTable {
  if (!existsSync(path)) {
    return {};
  }
  const parsed = parseToml(readFileSync(path, "utf-8"));
  if (!isRecord(parsed)) {
    throw new Error(`Invalid proxy TOML config: ${path}`);
  }
  const proxy = recordField(parsed, "proxy");
  const providers = recordField(proxy, "providers");
  const routing =
    recordField(proxy, "routing") ?? recordField(parsed, "routing");
  const mullvad =
    recordField(providers, "mullvad") ?? recordField(parsed, "mullvad");
  const resi =
    recordField(providers, "resi") ??
    recordField(providers, "resi-proxy") ??
    recordField(providers, "mysterium") ??
    recordField(parsed, "mysterium");
  const out: TomlTable = {};
  const forceProxy =
    boolField(parsed, "force_proxy") || boolField(routing, "force_proxy");
  if (forceProxy) {
    out.wisp = {
      proxy: {
        force_proxy: true,
      },
    };
  }
  const mullvadToml = mullvadProviderToml(mullvad);
  if (mullvadToml) {
    out.wisp_proxy_mullvad = mullvadToml;
  }
  const resiToml = residentialProviderToml(resi);
  if (resiToml) {
    out.wisp_proxy_resi = resiToml;
  }
  if (mullvadToml || resiToml) {
    out.wisp_proxy_control = { enabled: true };
    out.wisp_websocket = { proxy_control_enabled: true };
  }
  return out;
}

function mullvadProviderToml(section: ProviderSection): TomlTable | undefined {
  if (!section) return;
  const config: TomlTable = {
    enabled: true,
    relay_api: stringField(section, "relay_api") ?? DEFAULT_MULLVAD_API,
  };
  const wireproxySocks5 = stringField(section, "wireproxy_socks5");
  if (wireproxySocks5) {
    config.wireproxy_socks5 = wireproxySocks5;
  }
  return config;
}

function residentialProviderToml(
  section: ProviderSection,
): TomlTable | undefined {
  if (!section) return;
  const bearerToken =
    stringField(section, "bearer_token") ??
    envField(section, "bearer_token_env", [
      "ST_RESI_BEARER_TOKEN",
      "MYSTERIUM_BEARER_TOKEN",
      "ST_MYSTERIUM_BEARER_TOKEN",
    ]);
  const wireproxySocks5 = stringField(section, "wireproxy_socks5");
  if (bearerToken && wireproxySocks5) {
    throw new Error(
      "Mysterium config cannot combine bearer_token and wireproxy_socks5",
    );
  }
  if (wireproxySocks5) {
    return {
      enabled: true,
      wireproxy_socks5: wireproxySocks5,
    };
  }
  if (!bearerToken) return;
  const config: TomlTable = {
    enabled: true,
    bearer_token: bearerToken,
    api_base: stringField(section, "api_base") ?? DEFAULT_MYSTERIUM_API,
    country: stringField(section, "country") ?? "US",
    ip_type: stringField(section, "ip_type") ?? "residential",
  };
  const cookie =
    stringField(section, "cookie") ??
    envField(section, "cookie_env", [
      "ST_RESI_COOKIE",
      "MYSTERIUM_COOKIE",
      "ST_MYSTERIUM_COOKIE",
    ]);
  if (cookie) {
    config.cookie = cookie;
  }
  return config;
}

function envField(
  section: TomlRecord,
  key: string,
  fallbacks: string[],
): string | undefined {
  const configuredKey = stringField(section, key);
  if (configuredKey) {
    const val = process.env[configuredKey]?.trim();
    if (val) return val;
  }
  for (const fallback of fallbacks) {
    const val = process.env[fallback]?.trim();
    if (val) return val;
  }
}

function recordField(
  input: TomlRecord | undefined,
  key: string,
): TomlRecord | undefined {
  if (!input) return;
  const val = input[key];
  return isRecord(val) ? val : undefined;
}

function stringField(
  input: TomlRecord | undefined,
  key: string,
): string | undefined {
  if (!input) return;
  const val = input[key];
  return typeof val === "string" && val.trim() ? val.trim() : undefined;
}

function boolField(input: TomlRecord | undefined, key: string): boolean {
  if (!input) return false;
  return input[key] === true;
}

function isRecord(input: unknown): input is TomlRecord {
  return typeof input === "object" && input !== null && !Array.isArray(input);
}

function normalizeMountPath(path: string): string {
  const normalized = path.startsWith("/") ? path : `/${path}`;
  return normalized.length > 1 ? normalized.replace(/\/+$/, "") : normalized;
}

function rewriteMountPath(path: string, from: string, to: string): string {
  const normalizedFrom = normalizeMountPath(from);
  const normalizedTo = normalizeMountPath(to);
  const marker = path.search(/[?#]/);
  const pathname = marker === -1 ? path : path.slice(0, marker);
  if (!pathMatchesMount(pathname, normalizedFrom)) {
    return path;
  }
  const suffix =
    normalizedFrom === "/" ? path : path.slice(normalizedFrom.length);
  if (!suffix) {
    return normalizedTo;
  }
  if (suffix.startsWith("?") || suffix.startsWith("#")) {
    return `${normalizedTo}${suffix}`;
  }
  return `${normalizedTo}${suffix.startsWith("/") ? suffix : `/${suffix}`}`;
}

function proxyMatchPath(path: string): string {
  if (path === "/") {
    return "^/";
  }
  const escaped = path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return `^${escaped}(?:[/?#]|$)`;
}
