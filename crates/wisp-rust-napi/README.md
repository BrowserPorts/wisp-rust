# wisp-rust-napi

Native NAPI bindings for embedding `wisp-rust` from Bun or Node.

## Scope

This crate exposes Wisp runtime and proxy-routing controls only. It does not contain Scramjet session helpers or browser-specific APIs.

## Construction

```ts
import { WispRust } from "wisp-rust-napi";

const wisp = WispRust.fromTomlPath("./wisp.toml");
await wisp.start();
```

The runtime can be created from:

- `WispRust.fromTomlPath(path)`
- `WispRust.fromToml(toml, source?)`
- `WispRust.fromConfig(config)`

`fromConfig` accepts either the parsed Wisp TOML shape or a wrapper with `tomlPath`, `toml`, `source`, `config`, `benchMode`, and `logLevel`.

## Proxy Routing API

```ts
await wisp.setRoute({
  routeId: "palantir-account-a",
  targetUrls: ["https://stellite.usw-16.palantirfoundry.com"],
  provider: "mysterium",
  country: "US",
  ipType: "residential"
});

await wisp.rotateRoute("palantir-account-a");
```

Available methods:

- `start()`, `stop()`, `status()`, `boundUrls()`
- `setRoute(route)`, `removeRoute(routeId)`, `listRoutes()`, `rotateRoute(routeId)`
- `locations(provider?)`, `refreshLocations(provider?)`, `providerStatus()`
- `egressInventory()`, `blockEgressIp(ip)`, `releaseEgressIp(ip)`
- `getPolicy()`, `setPolicy(policy)`

## Bun Version Differences

- The Bun implementation controlled Wisp and proxy switching from TypeScript. This crate moves runtime start/stop, provider construction, route state, and egress blocking into Rust behind NAPI.
- The Bun implementation could mutate TypeScript provider controllers directly. This crate uses `ProxyControllerTemplate` as the shared Rust state that both the NAPI handle and accepted Wisp connections read from.
- The Bun implementation could accidentally drift from Rust server behavior. This crate starts from the same TOML parsing and provider registry used by `wisp-core`.
- The Bun implementation opened direct TCP sockets inside Wisp unless caller code replaced the transport. The Rust stream bridge now asks `ProxyController::connect_tcp`; matching routes and `forceProxy` fail closed when provider resolution fails.
- Scramjet-specific session creation is intentionally excluded. Scramjet should use the bound Wisp URL and manage browser frames in TypeScript.
