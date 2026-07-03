# wisp-wt-ts

`wisp-wt-ts` provides a Wisp server over WebSocket and WebTransport.

The WebSocket server uses `crossws` and can run on Node or Bun. WebTransport is exposed through selectable engines:

- `bun`: `@webtransport-bun/webtransport`, available on supported Node and Bun platforms.
- `fails`: `@fails-components/webtransport`, Node-only and optional.

WebTransport uses HTTP/3/QUIC, so it is a separate UDP listener rather than the same Node or Bun HTTP server object used for WebSockets. It can share the same numeric port only when the deployment environment allows TCP and UDP listeners on that port.

Origin policy is enforced from the browser `Origin` request header wherever the selected transport exposes request headers. Blank origins are blocked by default. Destination domain allowlists and blocklists are configurable through `domain_whitelist` and `domain_blacklist`; when either is configured, direct-IP access is blocked unless `allow_direct_ip_with_domain_policy` is enabled. Protocol inspection is enabled by default and allows only HTTP, HTTPS, HTTP/2, WebSocket, and H3 candidates on ports `80` and `443` unless configured otherwise.

Rate limiting uses Redis automatically when `redis_rate_limit_url` or `REDIS_URL` is configured; otherwise it falls back to the in-memory store for local development. See [DEPLOY.md](./DEPLOY.md) for production defaults, DoS controls, and status code tables.

## Subpaths

- `wisp-wt-ts/inspection` exports protocol inspection internals so other Wisp servers can reuse the same HTTP, TLS ClientHello, WebSocket, HTTP/2 HPACK, and QUIC Initial checks without importing the server.
- `wisp-wt-ts/proxy` exports the proxy controller, provider base class, Mullvad and residential providers, location helpers, and TCP proxy tunnel helpers.

## Local Benchmarks

Run the Bun path:

```sh
bun run bench:local
```

Run the Node path:

```sh
bun run bench:local:node
```

The benchmark labels are `wisp-wt-ts-wt`, `wisp-wt-ts-ws`, and `wisp-wt-ts-ws-fails`. The fails-components variant is run in a subprocess because the native module can terminate the process on local failures. Increase the local smoke size with `WISP_WT_BENCH_STREAMS` and `WISP_WT_BENCH_BYTES`. The default mode is paced echo traffic; set `WISP_WT_BENCH_MODE=full-duplex` to stress stream queueing. Set `WISP_WT_FAILS_CLIENT=native` to try the fails-components client instead of the common WebTransport client.
