### Structure

```json
{
  "name": "",
  "url": "",
  "user_agent": "",
  "process": [
    {
      "filter": [],
      "filter_server": [],
      "exclude": [],
      "filter_type": [],
      "exclude_type": [],
      "invert": false,
      "remove": false,
      "rename": {},
      "remove_emoji": false,
      "rewrite_multiplex": {},
      "rewrite_dialer_options": {},
      "rewrite_tls": {},
      "rewrite_vmess_options": {
        "security": ""
      },
      "rewrite_packet_encoding": "",
      "rewrite_quic_congestion_control": "",
      "rewrite_bbr_profile": null,
      "rewrite_utls": {
        "enabled": false,
        "fingerprint": ""
      }
    }
  ],
  "deduplication": false,
  "update_interval": "5m",
  "generate_selector": false,
  "generate_urltest": false,
  "urltest_suffix": "",
  "custom_selector": {},
  "custom_urltest": {}
}
```

### Fields

#### name

==Required==

Name of the subscription, will be used in group tags.

#### url

==Required==

Subscription URL.

Supports:

- HTTP/HTTPS URLs: `https://example.com/subscription`
- oixCloud managed URLs: `oixcloud://<token>` (query parameters are forwarded unchanged)
- Local file paths: `./subscriptions/nodes.txt` or `/absolute/path/to/nodes.txt`
- File URI: `file:///path/to/nodes.txt`

!!! note ""

    Relative file paths are resolved relative to the configuration file directory.

#### oixCloud managed subscriptions

`oixcloud://` subscriptions use the same Clash.Meta parser, conversion pipeline, process rules, cache, and template rendering as ordinary Clash subscriptions. Serenity requests the primary oixCloud API first and falls back to the secondary API when the primary response cannot be fetched, authenticated, decrypted, or parsed.

Every request uses a temporary age X25519 recipient. Serenity requires a valid HMAC-SHA256 response signature and an age-armored encrypted configuration; missing signatures, plaintext responses, invalid armor, or failed decryption are rejected. Credentials and complete managed URLs are never included in errors or logs. A refresh updates the bbolt cache only after verification, decryption, and parsing produce at least one valid outbound or endpoint, so a failed refresh preserves the last valid content and timestamp.

Requests advertise `X-Flclash-Build: 2026101003`, `X-oixCloud-Client: flclash`, and `X-oixCloud-Capabilities: snell.ech.h3=1`, matching the reference oixfetch client. These headers do not change the HMAC signature input.

The supported protocol set is the runnable intersection of the pinned FlClash Clash.Meta parser and the oixCloud sing-box fork based on `v1.14.3`:

- Outbounds: AnyTLS, Direct, HTTP, Hysteria, Hysteria2, Reject (as Block), Snell, SOCKS5, Shadowsocks, SSH, Trojan, TUIC, VLESS, and VMess.
- Endpoints: WireGuard, OpenVPN (as an OpenVPN client), and Tailscale.

Unsupported Clash-only types are reported by name while other valid entries in the same subscription remain available. Subscription endpoints are automatically merged into the profile's `endpoints` and their tags participate in generated selectors, URLTests, extra groups, default groups, filtering, renaming, emoji removal, and duplicate-tag handling. Outbound-specific rewrite fields continue to affect outbounds only.

The binary must be built with `OIXCLOUD_SUBSCRIPTION_HMAC_KEY`; builds without it continue to support all non-oixCloud subscription sources and return a clear error only when an `oixcloud://` URL is used. See [Build from source](../installation/build-from-source.md).

##### Snell ECH-TLS transport

Clash Snell nodes support `obfs-opts.transport`:

| Value | Generated sing-box transport |
| --- | --- |
| Omitted or `tcp` | No `transport` field; existing TCP ECH-TLS behavior |
| `h3` | `type: "http3"`, Happy Eyeballs disabled (HTTP/3 only) |
| `auto` | `type: "http3"`, `happy_eyeballs: true` |

In `auto` mode the core starts HTTP/3 first, then races verified ECH-TLS TCP after a short delay (or immediately if HTTP/3 fails). The first verified transport wins before Snell authentication or application data is sent. This replaces the old sequential TCP fallback.

The old native sing-box field `transport.fallback` is no longer accepted; replace it with `transport.happy_eyeballs`. Cached subscriptions containing the old field cannot be loaded and are fetched again on startup; refresh them successfully before relying on offline operation. Regenerated configurations require a client core supporting `happy_eyeballs`.

Converted HTTP/3 nodes explicitly use `quic_congestion_control: "reno"`, matching the upstream default. Native sing-box subscriptions retain their transport, congestion controller, and BBR profile unchanged unless a process rewrite is configured.

HTTP/3 requires Snell v4, identity v2, ECH, and certificate verification. Combining it with identity v1, `legacy-fallback: true`, or disabled certificate verification is rejected rather than silently converted to TCP. Unknown transport values are rejected. Other valid nodes remain available.

The TCP ALPN remains `snell-ech/1`; the core selects `h3` for HTTP/3. SNI, ECH, reuse, preconnect, UDP, and TFO settings are preserved. Legacy `obfs-opts.path` is ignored, as in the source client: the core derives the HTTP/3 tunnel path from the PSK, not from a WebSocket configuration.

The **client sing-box binary** must include `with_quic` to use HTTP/3, including `auto` mode. The TCP transport using a uTLS fingerprint also requires `with_utls`.

#### user_agent

User-Agent in HTTP request.

`serenity/$version (sing-box $sing-box-version; Clash compatible)` is used by default.

#### process

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

Process rules for filtering and renaming subscription outbounds and endpoints, and for modifying outbounds.

#### process.filter

Regexp filter rules, match outbound or endpoint tag name.

Only outbounds matching these patterns will be processed.

#### process.filter_server

Regexp filter rules, match the `server` field (node address) of an outbound or endpoint.

Only nodes with a matching server address will be processed. Nodes without a `server` field do not match this filter.

#### process.exclude

Regexp exclude rules, match outbound tag name.

Outbounds matching these patterns will be excluded from processing.

#### process.filter_type

Filter rules, match outbound or endpoint type (e.g., `vmess`, `vless`, `trojan`, `wireguard`).

#### process.exclude_type

Exclude rules, match outbound type.

#### process.invert

Invert filter results.

#### process.remove

Remove outbounds or endpoints that match the rules.

#### process.rename

Regexp rename rules; matching outbounds and endpoints will be renamed.

```json
{
  "rename": {
    "^prefix-(.*)": "$1",
    "old-name": "new-name"
  }
}
```

#### process.remove_emoji

Remove emojis in outbound tags.

#### process.rewrite_multiplex

Rewrite [Multiplex](https://sing-box.sagernet.org/configuration/shared/multiplex) options for Shadowsocks, Trojan, VMess, and VLESS outbounds.

#### process.rewrite_dialer_options

Rewrite [Dialer](https://sing-box.sagernet.org/configuration/shared/dial) options for outbounds.

#### process.rewrite_tls

Rewrite [TLS](https://sing-box.sagernet.org/configuration/shared/tls/#outbound) options for TLS-capable outbounds.

#### process.rewrite_vmess_options

Rewrite VMess options (currently supports `security`).

##### process.rewrite_vmess_options.security

Rewrite VMess security type.

#### process.rewrite_packet_encoding

Rewrite packet encoding for VMess and VLESS outbounds.

Available values: `packetaddr`, `xudp`.

#### process.rewrite_utls

Rewrite uTLS options for TLS-enabled outbounds (VMess, VLESS, Trojan, AnyTLS).

```json
{
  "rewrite_utls": {
    "enabled": true,
    "fingerprint": "chrome"
  }
}
```

##### process.rewrite_utls.enabled

Enable or disable uTLS.

##### process.rewrite_utls.fingerprint

Specify the uTLS fingerprint to use.

Available values: `chrome`, `firefox`, `edge`, `safari`, `360`, `qq`, `ios`, `android`, `random`, `randomized`.

#### process.rewrite_quic_congestion_control

Rewrite the congestion controller on matching Snell HTTP/3 outbounds. Values: `reno`, `cubic`, or `bbr`. An omitted or empty value leaves the controller unchanged. This does not enable HTTP/3 on TCP nodes or change other protocols or endpoints.

Switching to `reno` or `cubic` also clears any BBR profile. Selecting `bbr` preserves an existing profile, or uses the core's `standard` default if no profile is set.

#### process.rewrite_bbr_profile

Rewrite the BBR profile on matching Snell HTTP/3 outbounds. Values: `standard`, `conservative`, or `aggressive`. A nonempty profile requires `rewrite_quic_congestion_control: "bbr"` in the same process rule; invalid values or combinations are rejected when loading the process options.

Omit the field or use `null` to leave the profile unchanged. Use `""` to clear it and restore the core's default. Process rules run in their configured order and use the existing filter semantics.

```json
{
  "filter_type": ["snell"],
  "rewrite_quic_congestion_control": "bbr",
  "rewrite_bbr_profile": "conservative"
}
```

#### deduplication

Remove outbounds with duplicate server destinations (Domain will be resolved to compare).

Duplicate tag handling is controlled by `deduplication_strategy` in the template configuration.

#### update_interval

Subscription update interval.

`1h` is used by default.

#### generate_selector

Generate a global `Selector` outbound for the subscription.

If both `generate_selector` and `generate_urltest` are disabled, subscription outbounds will be added to global groups.

#### generate_urltest

Generate a global `URLTest` outbound for the subscription.

If both `generate_selector` and `generate_urltest` are disabled, subscription outbounds will be added to global groups.

#### urltest_suffix

Tag suffix of generated `URLTest` outbound.

` - URLTest` is used by default.

#### custom_selector

Custom [Selector](https://sing-box.sagernet.org/configuration/outbound/selector/) template.

#### custom_urltest

Custom [URLTest](https://sing-box.sagernet.org/configuration/outbound/urltest/) template.
