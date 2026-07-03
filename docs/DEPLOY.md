# Deploying wisp-wt-ts

`wisp-wt-ts` should be deployed behind normal edge controls. The server rejects obvious misuse locally, but TCP SYN floods and QUIC packet floods reach the host before Wisp, WebSocket, WebTransport, or protocol inspection can run.

## Defaults

| Setting                                  |                                  Default | Notes                                                                                            |
| ---------------------------------------- | ---------------------------------------: | ------------------------------------------------------------------------------------------------ |
| `port_whitelist`                         |                              `[80, 443]` | Only web-server ports are reachable by default.                                                  |
| `port_blacklist`                         |                                   `null` | Prefer allowlists for production.                                                                |
| `domain_whitelist`                       |                                   `null` | Optional allowed destination domains. `hostname_whitelist` is still accepted as an alias.        |
| `domain_blacklist`                       |                                   `null` | Optional blocked destination domains. `hostname_blacklist` is still accepted as an alias.        |
| `allow_direct_ip`                        |                                   `true` | Allows public direct-IP destinations when no stricter domain policy is configured.               |
| `allow_direct_ip_with_domain_policy`     |                                  `false` | Direct-IP destinations are blocked when either domain list is configured unless this is enabled. |
| `protocol_inspection`                    |                                   `true` | Defers TCP upstream connect until web protocol bytes are accepted.                               |
| `protocol_inspection_allowed_protocols`  | `["http", "https", "http2", "ws", "h3"]` | Configure this to narrow allowed visible protocols.                                              |
| `protocol_inspection_allow_quic_initial` |                                  `false` | H3/QUIC stays default-off unless explicitly enabled.                                             |
| `block_blank_origins`                    |                                   `true` | Blocks missing and `null` browser origins.                                                       |
| `allow_private_ips`                      |                                  `false` | Blocks RFC1918, link-local, multicast, documentation, and related ranges.                        |
| `allow_loopback_ips`                     |                                  `false` | Attempts to reach localhost close the connection and record a security ban.                      |
| `localhost_violation_ban_ms`             |                                `1800000` | 30 minute default ban for localhost attempts.                                                    |
| `security_violation_ban_ms`              |                                `1800000` | 30 minute default ban for protocol inspection violations.                                        |
| `rate_limit_backend`                     |                                   `auto` | Uses Redis when `redis_rate_limit_url` or `REDIS_URL` is set, otherwise memory.                  |
| `redis_rate_limit_url`                   |                                   `null` | Redis URL for distributed rate limiting.                                                         |
| `redis_rate_limit_key_prefix`            |                                `wisp-wt` | Prefix for Redis rate limit keys.                                                                |
| `redis_rate_limit_hash_tag`              |                             `rate-limit` | Redis Cluster hash tag so multi-key Lua checks share one slot.                                   |
| `redis_rate_limit_fail_open`             |                                  `false` | Redis failures deny rate-limited actions unless explicitly enabled.                              |

## Rate Limits

| Setting                                          |   Default | Trigger                                                                      |
| ------------------------------------------------ | --------: | ---------------------------------------------------------------------------- |
| `max_connection_starts_per_ip_per_minute`        |     `120` | WebSocket or WebTransport session starts per client IP.                      |
| `max_connection_starts_per_minute`               |    `4096` | Global session starts.                                                       |
| `max_connections_per_ip`                         |      `32` | Active sessions per client IP.                                               |
| `max_connections`                                |     `512` | Active sessions globally.                                                    |
| `max_tcp_stream_opens_per_connection_per_minute` |     `120` | TCP stream opens inside one Wisp connection.                                 |
| `max_tcp_stream_opens_per_ip_per_minute`         |     `480` | TCP stream opens by client IP.                                               |
| `max_tcp_bytes_per_connection_per_second`        |  `64 MiB` | Client-to-upstream TCP bytes per Wisp connection.                            |
| `max_tcp_bytes_per_ip_per_second`                | `256 MiB` | Client-to-upstream TCP bytes per client IP.                                  |
| `max_datagrams_per_connection_per_second`        |    `4096` | UDP/WebTransport datagrams per Wisp connection.                              |
| `max_datagram_bytes_per_connection_per_second`   |  `32 MiB` | UDP/WebTransport datagram bytes per Wisp connection.                         |
| `max_datagrams_per_ip_per_second`                |   `16384` | UDP/WebTransport datagrams per client IP.                                    |
| `max_datagram_bytes_per_ip_per_second`           | `128 MiB` | UDP/WebTransport datagram bytes per client IP.                               |
| `datagram_rate_limit_strikes`                    |       `3` | Over-limit datagrams are dropped first.                                      |
| `datagram_rate_limit_strike_window_ms`           |   `10000` | After 3 over-limit one-second windows inside this window, close with `1013`. |
| `max_control_messages_per_connection_per_minute` |      `60` | Proxy-control messages per Wisp connection.                                  |
| `max_control_messages_per_ip_per_minute`         |     `240` | Proxy-control messages per client IP.                                        |
| `max_dns_resolutions_per_ip_per_minute`          |     `120` | Resolver work per client IP.                                                 |
| `max_dns_resolutions_per_minute`                 |    `2048` | Resolver work globally.                                                      |
| `max_unique_hostnames_per_ip_per_minute`         |      `60` | Hostname spray limit per client IP.                                          |

Set a numeric limit to `-1` to disable that specific limiter.

## Destination Domain Policy

`domain_whitelist` and `domain_blacklist` match exact domains, subdomains, `*.example.com` wildcard suffixes, and `/regex/` entries. When either list is configured, direct-IP destinations are blocked by default even if they are public IPs. Set `allow_direct_ip_with_domain_policy: true` only if direct public IP access is intentionally part of the deployment policy.

## Redis Rate Limiting

Production deployments should use Redis so per-IP and global limits apply across all Wisp workers:

```ts
const options = {
  ...DEFAULT_WISP_OPTIONS,
  rate_limit_backend: "redis",
  redis_rate_limit_url: process.env.REDIS_URL ?? null,
};
```

`rate_limit_backend: "auto"` uses Redis whenever `redis_rate_limit_url` or `REDIS_URL` exists. Per-connection counters and datagram strike state remain local to the active Wisp connection because they do not need cross-worker coordination.

## Proxy Provider Limits

Proxy hop limits can be overridden per provider in `proxy-config.toml`:

```toml
[proxy-provider.mullvad]
max_session_hops = 16
max_daily_hops_per_ip = 100

[proxy-provider.resi-proxy]
max_session_hops = 8
max_daily_hops_per_ip = 50
```

`proxy-provider.resi`, `proxy-provider.resi-proxy`, and `proxy-provider.mysterium` all target the residential proxy provider. Omitted values fall back to `max_session_hops` and `max_daily_hops_per_ip` from the Wisp options.

## Required Edge Controls

| Risk                                 | Required mitigation                                                                                                  |
| ------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| TCP SYN floods                       | OS, load balancer, or CDN SYN protection. Application protocol inspection cannot run before TCP handshakes complete. |
| WebSocket handshake floods           | CDN/load balancer HTTP upgrade rate limits plus `max_connection_starts*`.                                            |
| WebTransport/QUIC floods             | Provider UDP/QUIC rate limits plus `max_connection_starts*` and datagram limits.                                     |
| Random-host DNS abuse                | Keep DNS limits enabled and use resolver-level caching where possible.                                               |
| Fake usage/control spam              | Keep proxy control rate limits enabled and authenticate usage reporting outside this package.                        |
| Localhost or private network probing | Keep `allow_loopback_ips` and `allow_private_ips` disabled unless running trusted private infrastructure.            |

## HTTP Statuses

| Status | Where                                                  | Meaning                                                      |
| -----: | ------------------------------------------------------ | ------------------------------------------------------------ |
|  `403` | WebSocket upgrade, fails WebTransport request callback | Origin policy rejected the request.                          |
|  `500` | `createWispUpgradeResponse` fallback                   | WebSocket upgrade failed before a transport was established. |

## WebSocket and WebTransport Close Codes

|   Code | Reason                           | Meaning                                                             |
| -----: | -------------------------------- | ------------------------------------------------------------------- |
| `1000` | `closed`                         | Normal WebTransport control close.                                  |
| `1001` | `idle_timeout`                   | No connection activity before the configured idle timer.            |
| `1002` | `invalid_packet`, `invalid_info` | Malformed Wisp or Wisp-WT protocol data.                            |
| `1008` | `origin_blocked`                 | Origin policy blocked the browser origin.                           |
| `1008` | `client_blocked`                 | Client IP allow/deny policy blocked the connection.                 |
| `1008` | `localhost_blocked`              | Destination was localhost or resolved to localhost.                 |
| `1008` | `security_blocked`               | Protocol inspection rejected non-web or unsafe traffic.             |
| `1008` | `handshake_timeout`              | Wisp or Wisp-WT handshake did not complete in time.                 |
| `1009` | `frame_too_large`                | WebSocket frame exceeded `max_binary_frame_bytes`.                  |
| `1011` | `open_failed`                    | Server failed while opening a WebSocket Wisp connection.            |
| `1013` | `security_rate_limited`          | Client IP is temporarily banned after localhost or security misuse. |
| `1013` | `connection_limit`               | Active connection cap was exceeded.                                 |
| `1013` | `connection_rate_limited`        | Connection start rate cap was exceeded.                             |
| `1013` | `tcp_rate_limited`               | TCP byte-rate limit was exceeded.                                   |
| `1013` | `datagram_rate_limited`          | Datagram limit exceeded repeatedly after drop-first handling.       |
| `1013` | `control_rate_limited`           | Proxy-control message rate cap was exceeded.                        |

## Wisp Stream Close Reasons

|   Code | Name                     | Meaning                                                                   |
| -----: | ------------------------ | ------------------------------------------------------------------------- |
| `0x01` | `Unknown`                | Unclassified close reason.                                                |
| `0x02` | `Voluntary`              | Local or remote normal stream close.                                      |
| `0x03` | `NetworkError`           | Socket, UDP, or transport I/O failed.                                     |
| `0x04` | `IncompatibleExtensions` | Extension negotiation failed.                                             |
| `0x41` | `InvalidInfo`            | Malformed open, info, frame, or stream metadata.                          |
| `0x42` | `UnreachableHost`        | DNS or destination reachability failed.                                   |
| `0x43` | `NoResponse`             | Upstream did not respond.                                                 |
| `0x44` | `ConnRefused`            | Upstream refused the connection.                                          |
| `0x45` | `ProxyRotated`           | Proxy-control provider rotation closed streams.                           |
| `0x47` | `TransferTimeout`        | Stream idle timeout fired.                                                |
| `0x48` | `HostBlocked`            | Destination, protocol, port, IP range, or host policy blocked the stream. |
| `0x49` | `ConnThrottled`          | Stream, DNS, or open-rate limits throttled the request.                   |
| `0x81` | `ClientError`            | Client-side stream error.                                                 |
| `0xc0` | `AuthBadPassword`        | Authentication failed because the password was wrong.                     |
| `0xc1` | `AuthBadSignature`       | Authentication failed because the signature was wrong.                    |
| `0xc2` | `AuthMissingCredentials` | Authentication failed because credentials were missing.                   |
