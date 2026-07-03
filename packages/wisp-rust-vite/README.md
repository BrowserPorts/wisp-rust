# wisp-rust-vite

TypeScript package for using `wisp-rust-napi` from Vite.

## Install

This package is currently local to the `wisp-rust` repository and depends on the sibling native package:

```json
{
  "dependencies": {
    "wisp-rust-vite": "file:packages/wisp-rust-vite"
  }
}
```

## Vite Plugin

```ts
import { defineConfig } from "vite";
import { wispRustVite } from "wisp-rust-vite";

export default defineConfig({
  plugins: [
    wispRustVite({
      tomlPath: "./configs/wispd.production.toml",
      proxyConfigPath: "../../packages/api/proxy-config.toml",
      proxyPath: "/wisp"
    })
  ]
});
```

The plugin:

- Creates a native `WispRust` runtime from TOML, TOML text, or parsed config.
- Can merge a Stellite `proxy-config.toml` into the Rust provider sections.
- Starts the Rust WebSocket Wisp listener during dev and preview by default.
- Adds a Vite reverse proxy entry for the configured Wisp endpoint.
- Stops the native runtime when the Vite HTTP server closes.

## Runtime API

```ts
import { createWispRustRuntime } from "wisp-rust-vite";

const wisp = createWispRustRuntime({
  tomlPath: "./configs/wispd.production.toml"
});

await wisp.start();

await wisp.setRoute({
  routeId: "palantir-account-a",
  targetUrls: ["https://stellite.usw-16.palantirfoundry.com"],
  provider: "mysterium",
  country: "US",
  ipType: "residential"
});
```

Exported methods mirror the native package:

- `start()`, `stop()`, `status()`, `boundUrls()`
- `setRoute(route)`, `removeRoute(routeId)`, `listRoutes()`, `rotateRoute(routeId)`
- `locations(provider?)`, `refreshLocations(provider?)`, `providerStatus()`
- `egressInventory()`, `blockEgressIp(ip)`, `releaseEgressIp(ip)`
- `getPolicy()`, `setPolicy(policy)`

Scramjet frame/session helpers are intentionally outside this package. This package owns Wisp startup, Vite proxying, and proxy-route control.
