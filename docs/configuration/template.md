### Structure

```json
{
  "name": "",
  "extend": "",
  
  // Global

  "log": {},
  "http_clients": [],
  "domain_strategy": "",
  "domain_strategy_local": "",
  "disable_traffic_bypass": false,
  "disable_sniff": false,
  "sniff_override_destination": "",
  "disable_rule_action": false,
  
  // DNS

  "dns": "",
  "dns_local": "",
  "dns_servers": [],
  "enable_fakeip": false,
  "pre_dns_rules": [],
  "custom_dns_rules": [],
  "custom_fakeip": {},
  "fakeip_rewrite_ttl": null,
  "inherit_fakeip_rewrite_ttl": false,
  
  // Inbound

  "inbounds": [],
  "auto_redirect": false,
  "disable_tun": false,
  "disable_system_proxy": false,
  "custom_tun": {},
  "custom_mixed": {},
  
  // Outbound

  "extra_groups": [
    {
      "tag": "",
      "type": "",
      "target": "",
      "tag_per_subscription": "",
      "filter": "",
      "exclude": "",
      "custom_selector": {},
      "custom_urltest": {}
    }
  ],
  "direct_tag": "",
  "default_tag": "",
  "urltest_tag": "",
  "urltest_url": "",
  "disable_preconnect": false,
  "deduplication_strategy": "",
  "custom_direct": {},
  "custom_selector": {},
  "custom_urltest": {},
  
  // Route

  "default_http_client": "",
  "pre_rules": [],
  "custom_rules": [],
  "enable_jsdelivr": false,
  "custom_geoip": {},
  "custom_geosite": {},
  "custom_rule_set": [],
  "post_rule_set": [],
  
  // Experimental

  "disable_cache_file": false,
  "disable_clash_mode": false,
  "enable_unified_delay": false,
  "clash_mode_rule": "",
  "clash_mode_global": "",
  "clash_mode_direct": "",
  "custom_clash_api": {},
  
  // Debug

  "pprof_listen": "",
  "memory_limit": ""
}
```

### Fields

#### name

==Required==

Profile name.

#### extend

Extend from another profile.

#### log

Log configuration, see [Log](https://sing-box.sagernet.org/configuration/log/).

#### http_clients

List of [HTTP Client](https://sing-box.sagernet.org/configuration/shared/http-client/) options.

For sing-box 1.14.0 and later, a default HTTP client will be generated for remote rule-set downloads if this field is empty.

#### domain_strategy

Global sing-box domain strategy.

One of `prefer_ipv4` `prefer_ipv6` `ipv4_only` `ipv6_only`.

If `*_only` enabled, TUN and DNS will be configured to disable the other network.

Note that if want `prefer_*` to take effect on transparent proxy requests, set `enable_fakeip`.

`ipv4_only` is used by default when `enable_fakeip` disabled,
`prefer_ipv4` is used by default when `enable_fakeip` enabled.

#### domain_strategy_local

Local sing-box domain strategy.

`prefer_ipv4` is used by default.

#### disable_sniff

Don`t generate protocol sniffing options.

#### sniff_override_destination

Controls whether the connection destination is replaced with a domain detected from HTTP, TLS, or QUIC.

One of `disabled`, `always`, or `if_resolvable`. The default is `disabled`.

For compatibility, `false` is equivalent to `disabled` and `true` is equivalent to `always`.

`if_resolvable` overrides the destination only when the detected domain is known to have a valid A or AAAA record.

#### disable_rule_action

Don`t generate rule action options.

#### disable_traffic_bypass

Disable traffic bypass for Chinese DNS queries and connections.

#### dns

Default DNS server.

`tls://8.8.8.8` is used by default.

#### dns_local

DNS server used for China DNS requests.

`114.114.114.114` is used by default.

#### dns_servers

List of [DNS Server](https://sing-box.sagernet.org/configuration/dns/server/).

Will be append to DNS servers.

#### enable_fakeip

Enable FakeIP.

#### pre_dns_rules

List of [DNS Rule](https://sing-box.sagernet.org/configuration/dns/rule/).

Will be applied before traffic bypassing rules.

#### custom_dns_rules

List of [DNS Rule](https://sing-box.sagernet.org/configuration/dns/rule/).

No default traffic bypassing DNS rules will be generated if not empty.

#### custom_fakeip

Custom [FakeIP](https://sing-box.sagernet.org/configuration/dns/fakeip/) template.

#### fakeip_rewrite_ttl

Rewrite TTL for generated FakeIP DNS rules.

Not set by default.

#### inherit_fakeip_rewrite_ttl

Apply `fakeip_rewrite_ttl` to top-level custom DNS rules that route directly to the generated FakeIP server.

Existing `rewrite_ttl` values are not overwritten.

#### inbounds

List of [Inbound](https://sing-box.sagernet.org/configuration/inbound/).

#### auto_redirect

Generate [auto-redirect](https://sing-box.sagernet.org/configuration/inbound/tun/#auto_redirect) options for android and unknown platforms.

#### disable_tun

Don't generate TUN inbound.

If the target platform can only use TUN for proxy (currently all Apple platforms), this item will not take effect.

#### disable_system_proxy

Don't generate `tun.platform.http_proxy` for known platforms and `set_system_proxy` for unknown platforms.

#### custom_tun

Custom [TUN](https://sing-box.sagernet.org/configuration/inbound/tun/) inbound template.

#### custom_mixed

Custom [Mixed](https://sing-box.sagernet.org/configuration/inbound/mixed/) inbound template.

#### extra_groups

Generate extra outbound groups.

#### extra_groups.tag

==Required==

Tag of the group outbound.

#### extra_groups.type

==Required==

Type of the group outbound.

#### extra_groups.target

| Value          | Description                                                |
|----------------|------------------------------------------------------------|
| `default`      | No additional behaviors.                                   |
| `global`       | Generate a group and add it to default selector.           |
| `subscription` | Generate a internal group for every subscription selector. |

#### extra_groups.tag_per_subscription

Tag for every new subscription internal group when `target` is `subscription`.

`{{ .tag }} ({{ .subscription_name }})` is used by default.

#### extra_groups.filter

Regexp filter rules, non-matching outbounds will be removed.

#### extra_groups.exclude

Regexp exclude rules, matching outbounds will be removed.

#### extra_groups.custom_selector

Custom [Selector](https://sing-box.sagernet.org/configuration/outbound/selector/) template.

#### extra_groups.custom_urltest

Custom [URLTest](https://sing-box.sagernet.org/configuration/outbound/urltest/) template.

#### direct_tag

Custom direct outbound tag.

#### default_tag

Custom default outbound tag.

#### urltest_tag

Custom URLTest outbound tag.

#### urltest_url

Default URL for URLTest outbounds.

Only URLTest outbounds without `url` set will use this value.

#### disable_preconnect

Set Snell `preconnect` to `0` when generating configurations for iOS and tvOS.

#### deduplication_strategy

Strategy for handling duplicate outbound tags across subscriptions within this template.

Available values:

- `rename` (default): Keep all outbounds, append suffix like `node (1)`, `node (2)`.
- `first`: Keep the first occurrence, discard duplicates.
- `last`: Keep the last occurrence, discard duplicates.
- `prefer_ipv4`: Prefer IPv4 > Domain > IPv6.
- `prefer_ipv6`: Prefer IPv6 > Domain > IPv4.
- `prefer_domain_then_ipv4`: Prefer Domain > IPv4 > IPv6.
- `prefer_domain_then_ipv6`: Prefer Domain > IPv6 > IPv4.

#### custom_direct

Custom [Direct](https://sing-box.sagernet.org/configuration/outbound/direct/) outbound template.

#### custom_selector

Custom [Selector](https://sing-box.sagernet.org/configuration/outbound/selector/) outbound template.

#### custom_urltest

Custom [URLTest](https://sing-box.sagernet.org/configuration/outbound/urltest/) outbound template.

#### pre_rules

List of [Rule](https://sing-box.sagernet.org/configuration/route/rule/).

Will be applied before traffic bypassing rules.

#### custom_rules

List of [Rule](https://sing-box.sagernet.org/configuration/route/rule/).

No default traffic bypassing rules will be generated if not empty.

#### enable_jsdelivr

Use jsDelivr CDN and direct outbound for default rule sets or Geo resources.

#### default_http_client

Default [HTTP Client](https://sing-box.sagernet.org/configuration/shared/http-client/) tag used by remote rule-sets.

Only generated for sing-box 1.14.0 and later.

#### custom_geoip

Custom [GeoIP](https://sing-box.sagernet.org/configuration/route/geoip/) template.

#### custom_geosite

Custom [GeoSite](https://sing-box.sagernet.org/configuration/route/geosite/) template.

#### custom_rule_set

List of [RuleSet](/configuration/shared/rule-set/).

Default rule sets will not be generated if not empty.

#### post_rule_set

List of [RuleSet](/configuration/shared/rule-set/).

Will be applied after default rule sets.

#### disable_cache_file

Don't generate `cache_file` related options.

#### disable_clash_mode

Don't generate `clash_mode` related options.

#### enable_unified_delay

Enable unified delay for URL tests on sing-box 1.14.0-beta.9 and later.

URL tests send a warm-up request and measure only a second request on the same connection, excluding connection establishment and TLS handshake time from the reported delay.

#### clash_mode_rule

Name of the 'Rule' Clash mode.

`Rule` is used by default.

#### clash_mode_global

Name of the 'Global' Clash mode.

`Global` is used by default.

#### clash_mode_direct

Name of the 'Direct' Clash mode.

`Direct` is used by default.

#### custom_clash_api

Custom [Clash API](https://sing-box.sagernet.org/configuration/experimental/clash-api/) template.

#### pprof_listen

Listen address of the pprof server.

#### memory_limit

Set soft memory limit for sing-box.

`100m` is recommended if memory limit is required.
