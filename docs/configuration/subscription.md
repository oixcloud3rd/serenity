### Structure

```json
{
  "name": "",
  "url": "",
  "user_agent": "",
  "process": [
    {
      "filter": [],
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
- Local file paths: `./subscriptions/nodes.txt` or `/absolute/path/to/nodes.txt`
- File URI: `file:///path/to/nodes.txt`

!!! note ""

    Relative file paths are resolved relative to the configuration file directory.

#### user_agent

User-Agent in HTTP request.

`serenity/$version (sing-box $sing-box-version; Clash compatible)` is used by default.

#### process

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

Process rules for filtering, renaming, and modifying outbounds.

#### process.filter

Regexp filter rules, match outbound tag name.

Only outbounds matching these patterns will be processed.

#### process.exclude

Regexp exclude rules, match outbound tag name.

Outbounds matching these patterns will be excluded from processing.

#### process.filter_type

Filter rules, match outbound type (e.g., `vmess`, `vless`, `trojan`, `shadowsocks`).

#### process.exclude_type

Exclude rules, match outbound type.

#### process.invert

Invert filter results.

#### process.remove

Remove outbounds that match the rules.

#### process.rename

Regexp rename rules, matching outbounds will be renamed.

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
