import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import { resolve } from "node:path";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import type { TomlTable, TomlValue } from "smol-toml";
import type { Plugin, ProxyOptions, UserConfig } from "vite";

export type WispRuntimeInput =
  | {
      tomlPath?: string;
      toml?: string;
      source?: string;
      config?: Record<string, unknown>;
      benchMode?: boolean;
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
  allowDirectIp?: boolean;
  allowDirectIpWithDomainPolicy?: boolean;
  allowPrivateIps?: boolean;
  allowLoopbackIps?: boolean;
};

export type WispAuthTokenHandlerResult =
  | WispAuthTokenPolicy
  | boolean
  | null
  | undefined;

export type WispAuthTokenHandler = (
  token: string
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
  benchMode?: boolean;
  logLevel?: string;
  cwd?: string;
  native?: WispRustNativeModule;
  resolvedWsPort?: number;
};

export type WispRustViteOptions = WispRustRuntimeOptions & {
  proxyPath?: string;
  autoStart?: boolean;
  startInPreview?: boolean;
  stopOnClose?: boolean;
  configureProxy?: (proxy: ProxyOptions, context: WispRustProxyContext) => ProxyOptions;
};

export type WispRustProxyContext = {
  boundUrl: URL;
  proxyPath: string;
  endpointPath: string;
  target: string;
};

type RuntimeStatus = Record<string, unknown>;
type RuntimeResult = Record<string, unknown>;
type ClosableServer = {
  once(event: "close", listener: () => unknown): unknown;
};
type TomlRecord = Record<string, TomlValue>;
type ProviderSection = TomlRecord | undefined;

const require = createRequire(import.meta.url);
const DEFAULT_MULLVAD_API = "https://api.mullvad.net/www/relays/wireguard/";
const DEFAULT_MYSTERIUM_API = "https://api.mysteriumvpn.com";
const DEFAULT_AUTHENTICATED_PROFILE = "authenticated";
const DEFAULT_AUTHENTICATED_PROVIDERS = ["mullvad", "resi", "mysterium"];
const MULTIPLIED_LIMIT_FIELDS = new Set([
  "streamLimitPerHost",
  "streamLimitTotal",
  "bufferSize",
  "continueThreshold",
  "maxConnectionsPerIp",
  "maxBinaryFrameBytes",
  "maxTextFrameBytes",
  "maxPendingPacketsPerStream",
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
  "protocolInspectionMaxBytes"
]);

export class WispRustRuntime {
  readonly native: WispRustNativeModule;
  readonly instance: WispRust;

  private startPromise: Promise<RuntimeStatus> | undefined;
  private stopPromise: Promise<RuntimeStatus> | undefined;

  constructor(options: WispRustRuntimeOptions = {}) {
    this.native = options.native ?? loadNative();
    this.instance = createNativeRuntime(this.native, options);
    configureAuthenticatedProfile(this.instance, options);
  }

  async start(): Promise<RuntimeStatus> {
    if (!this.startPromise) {
      this.startPromise = this.instance.start();
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
    const target = `${boundUrl.protocol}//${boundUrl.host}`;
    return {
      boundUrl,
      proxyPath: mountPath,
      endpointPath,
      target
    };
  }

  viteProxyOptions(options: Pick<WispRustViteOptions, "proxyPath" | "configureProxy"> = {}): {
    path: string;
    options: ProxyOptions;
  } {
    const context = this.proxyContext(options.proxyPath);
    const proxy: ProxyOptions = {
      target: context.target,
      ws: true,
      changeOrigin: true,
      secure: context.boundUrl.protocol === "wss:",
      rewrite:
        context.proxyPath === context.endpointPath
          ? undefined
          : (path) => rewriteMountPath(path, context.proxyPath, context.endpointPath)
    };
    return {
      path: proxyMatchPath(context.proxyPath),
      options: options.configureProxy?.(proxy, context) ?? proxy
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
      handler ? async (token) => normalizeAuthHandlerResult(await handler(token)) : undefined
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

export function createWispRustRuntime(options: WispRustRuntimeOptions = {}): WispRustRuntime {
  return new WispRustRuntime(options);
}

export function wispRustVite(options: WispRustViteOptions = {}): Plugin {
  let runtime: WispRustRuntime | undefined;
  let closeRegistered = false;
  let proxyConfig: { path: string; options: ProxyOptions } | undefined;
  let resolvedWsPort: number | undefined;

  const getRuntime = (root: string): WispRustRuntime => {
    if (!runtime) {
      runtime = createWispRustRuntime({
        ...options,
        cwd: options.cwd ?? root,
        resolvedWsPort
      });
    }
    return runtime;
  };

  const getProxyConfig = (root: string): { path: string; options: ProxyOptions } => {
    if (!proxyConfig) {
      proxyConfig = getRuntime(root).viteProxyOptions(options);
    }
    return proxyConfig;
  };

  const setupServer = async (
    httpServer: ClosableServer | null | undefined,
    root: string
  ) => {
    const activeRuntime = getRuntime(root);
    const shouldStart = options.autoStart ?? true;
    if (shouldStart) {
      await activeRuntime.start();
    }
    if ((options.stopOnClose ?? true) && httpServer && !closeRegistered) {
      closeRegistered = true;
      httpServer.once("close", () => {
        return activeRuntime.stop().catch(() => undefined);
      });
    }
  };

  return {
    name: "wisp-rust-vite",
    enforce: "pre",
    async config(config): Promise<UserConfig> {
      const root = resolve(config.root ?? process.cwd());
      resolvedWsPort =
        options.resolvedWsPort ??
        (await resolveFreeWsPort({
          ...options,
          cwd: options.cwd ?? root
        }));
      const proxy = getProxyConfig(root);
      return {
        server: {
          proxy: {
            [proxy.path]: proxy.options
          }
        },
        preview: {
          proxy: {
            [proxy.path]: proxy.options
          }
        }
      };
    },
    async configureServer(server) {
      await setupServer(server.httpServer, server.config.root);
    },
    async configurePreviewServer(server) {
      if (options.startInPreview ?? true) {
        await setupServer(server.httpServer, server.config.root);
      }
    }
  };
}

export const wispRustPlugin = wispRustVite;

function loadNative(): WispRustNativeModule {
  const explicitPath = process.env.WISP_RUST_NAPI_PATH?.trim();
  const workspaceRoot = process.env.ST_WORKSPACE_ROOT?.trim();
  const candidates = [
    explicitPath,
    workspaceRoot
      ? resolve(workspaceRoot, "wisp-rust/crates/wisp-rust-napi/index.js")
      : undefined
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

async function findFreePort(host: string, startPort: number, maxAttempts = 100): Promise<number> {
  let candidate = startPort;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    if (await isPortFree(candidate, host)) return candidate;
    candidate += 1;
  }
  return startPort;
}

async function resolveFreeWsPort(options: WispRustRuntimeOptions): Promise<number | undefined> {
  try {
    const ws = recordField(buildRuntimeTomlTable(options), "wisp_websocket");
    if (!ws || ws.enabled === false) return undefined;
    const host = typeof ws.host === "string" ? ws.host : "127.0.0.1";
    const basePort = typeof ws.port === "number" ? ws.port : 4142;
    return await findFreePort(host, basePort);
  } catch {
    return undefined;
  }
}

function createNativeRuntime(native: WispRustNativeModule, options: WispRustRuntimeOptions): WispRust {
  if (options.proxyConfigPath || options.authenticatedProxyConfigPath) {
    return native.WispRust.fromToml(
      mergedRuntimeToml(options),
      options.source ?? options.tomlPath ?? options.proxyConfigPath ?? options.authenticatedProxyConfigPath
    );
  }
  if (options.tomlPath) {
    if (options.resolvedWsPort !== undefined) {
      const table = parseRuntimeToml(
        readFileSync(resolvePath(options.tomlPath, options.cwd), "utf-8"),
        options.tomlPath
      );
      applyWsPortOverride(table, options.resolvedWsPort);
      return native.WispRust.fromToml(stringifyToml(table), options.tomlPath);
    }
    return native.WispRust.fromTomlPath(resolvePath(options.tomlPath, options.cwd));
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
      benchMode: options.benchMode,
      logLevel: options.logLevel
    });
  }
  if (options.benchMode !== undefined || options.logLevel !== undefined) {
    return native.WispRust.fromConfig({
      config: {},
      benchMode: options.benchMode,
      logLevel: options.logLevel
    });
  }
  return native.WispRust.fromConfig({
    config: {}
  });
}

function resolvePath(path: string, cwd = process.cwd()): string {
  return path.startsWith("/") ? path : resolve(cwd, path);
}

function buildRuntimeTomlTable(options: WispRustRuntimeOptions): TomlTable {
  const base = parseRuntimeToml(baseRuntimeToml(options), options.source ?? options.tomlPath);
  if (options.proxyConfigPath) {
    mergeTomlTables(base, proxyConfigTable(resolvePath(options.proxyConfigPath, options.cwd)));
  }
  if (options.authenticatedProxyConfigPath) {
    mergeTomlTables(
      base,
      proxyConfigTable(resolvePath(options.authenticatedProxyConfigPath, options.cwd))
    );
  }
  return base;
}

function mergedRuntimeToml(options: WispRustRuntimeOptions): string {
  const base = buildRuntimeTomlTable(options);
  applyWsPortOverride(base, options.resolvedWsPort);
  return stringifyToml(base);
}

function applyWsPortOverride(table: TomlTable, port: number | undefined): void {
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
  if (options.config || options.benchMode !== undefined || options.logLevel !== undefined) {
    throw new Error("proxyConfigPath requires tomlPath or toml");
  }
  return "";
}

function configureAuthenticatedProfile(instance: WispRust, options: WispRustRuntimeOptions) {
  const handler = options.authTokenHandler;
  const multiplier = options.authenticatedLimitMultiplier;
  const profileName = options.authenticatedProfileName ?? DEFAULT_AUTHENTICATED_PROFILE;
  const hasAuthenticatedProviderPolicy =
    Boolean(options.authenticatedProxyConfigPath) ||
    Boolean(options.authenticatedAllowedProxyProviders);
  if (multiplier !== undefined) {
    const normalizedMultiplier = Number.isFinite(multiplier)
      ? Math.max(1, Math.floor(multiplier))
      : 1;
    const baseLimits = instance.getLimits();
    const authenticatedLimits = multiplyWispLimits(baseLimits, normalizedMultiplier);
    instance.setLimitProfile(profileName, authenticatedLimits);
  }
  if (handler) {
    instance.setAuthTokenHandler(async (token) => {
      const policy = normalizeAuthHandlerResult(await handler(token));
      if (!policy) return null;
      if (multiplier === undefined && !hasAuthenticatedProviderPolicy) return policy;
      return {
        ...(multiplier === undefined ? {} : { limitProfile: profileName }),
        allowedProxyProviders:
          options.authenticatedAllowedProxyProviders ?? DEFAULT_AUTHENTICATED_PROVIDERS,
        ...policy
      };
    });
  }
}

function normalizeAuthHandlerResult(
  result: WispAuthTokenHandlerResult
): WispAuthTokenPolicy | null {
  if (result === true) return {};
  if (!result) return null;
  return result;
}

function multiplyWispLimits(limits: RuntimeResult, multiplier: number): RuntimeResult {
  const out = JSON.parse(JSON.stringify(limits)) as RuntimeResult;
  for (const key of MULTIPLIED_LIMIT_FIELDS) {
    const val = out[key];
    if (typeof val === "number" && Number.isFinite(val) && val > 0) {
      out[key] = Math.min(Number.MAX_SAFE_INTEGER, Math.floor(val * multiplier));
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
  const routing = recordField(proxy, "routing") ?? recordField(parsed, "routing");
  const mullvad = recordField(providers, "mullvad") ?? recordField(parsed, "mullvad");
  const resi =
    recordField(providers, "resi") ??
    recordField(providers, "resi-proxy") ??
    recordField(providers, "mysterium") ??
    recordField(parsed, "mysterium");
  const out: TomlTable = {};
  const forceProxy = boolField(parsed, "force_proxy") || boolField(routing, "force_proxy");
  if (forceProxy) {
    out.wisp = {
      proxy: {
        force_proxy: true
      }
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
  return out;
}

function mullvadProviderToml(section: ProviderSection): TomlTable | undefined {
  if (!section) return;
  const config: TomlTable = {
    enabled: true,
    relay_api: stringField(section, "relay_api") ?? DEFAULT_MULLVAD_API
  };
  const wireproxySocks5 = stringField(section, "wireproxy_socks5");
  if (wireproxySocks5) {
    config.wireproxy_socks5 = wireproxySocks5;
  }
  return config;
}

function residentialProviderToml(section: ProviderSection): TomlTable | undefined {
  if (!section) return;
  const bearerToken =
    stringField(section, "bearer_token") ??
    envField(section, "bearer_token_env", [
      "ST_RESI_BEARER_TOKEN",
      "MYSTERIUM_BEARER_TOKEN",
      "ST_MYSTERIUM_BEARER_TOKEN"
    ]);
  if (!bearerToken) return;
  const config: TomlTable = {
    enabled: true,
    bearer_token: bearerToken,
    api_base: stringField(section, "api_base") ?? DEFAULT_MYSTERIUM_API,
    country: stringField(section, "country") ?? "US",
    ip_type: stringField(section, "ip_type") ?? "residential"
  };
  const cookie =
    stringField(section, "cookie") ??
    envField(section, "cookie_env", ["ST_RESI_COOKIE", "MYSTERIUM_COOKIE", "ST_MYSTERIUM_COOKIE"]);
  if (cookie) {
    config.cookie = cookie;
  }
  return config;
}

function envField(section: TomlRecord, key: string, fallbacks: string[]): string | undefined {
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

function recordField(input: TomlRecord | undefined, key: string): TomlRecord | undefined {
  if (!input) return;
  const val = input[key];
  return isRecord(val) ? val : undefined;
}

function stringField(input: TomlRecord | undefined, key: string): string | undefined {
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
  if (!path.startsWith(from)) {
    return path;
  }
  const suffix = path.slice(from.length);
  if (!suffix) {
    return to;
  }
  return `${to}${suffix.startsWith("/") ? suffix : `/${suffix}`}`;
}

function proxyMatchPath(path: string): string {
  if (path === "/") {
    return "^/";
  }
  const escaped = path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return `^${escaped}(?:[/?#]|$)`;
}
