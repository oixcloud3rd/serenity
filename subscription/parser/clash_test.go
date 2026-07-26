package parser

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	boxTLS "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestParseClashFullProtocolIntersection(t *testing.T) {
	content := fmt.Sprintf(`proxies:
  - {name: direct-node, type: direct}
  - {name: reject-node, type: reject}
  - {name: ss-node, type: ss, server: 127.0.0.1, port: 10001, cipher: aes-128-gcm, password: secret, udp: true}
  - {name: socks-node, type: socks5, server: 127.0.0.1, port: 10002, username: user, password: pass, udp: true}
  - {name: http-node, type: http, server: 127.0.0.1, port: 10003, username: user, password: pass}
  - {name: vmess-node, type: vmess, server: 127.0.0.1, port: 10004, uuid: 00000000-0000-0000-0000-000000000001, alterId: 0, cipher: auto, udp: true}
  - {name: vless-node, type: vless, server: 127.0.0.1, port: 10005, uuid: 00000000-0000-0000-0000-000000000002, udp: true}
  - {name: trojan-node, type: trojan, server: 127.0.0.1, port: 10006, password: secret, sni: example.com, skip-cert-verify: true, udp: true}
  - {name: anytls-node, type: anytls, server: 127.0.0.1, port: 10007, password: secret, sni: example.com, skip-cert-verify: true, udp: true}
  - {name: hysteria-node, type: hysteria, server: 127.0.0.1, port: 10008, up: 100 Mbps, down: 100 Mbps, auth-str: secret, sni: example.com, skip-cert-verify: true}
  - {name: hysteria2-node, type: hysteria2, server: 127.0.0.1, port: 10009, password: secret, sni: example.com, skip-cert-verify: true}
  - {name: tuic-node, type: tuic, server: 127.0.0.1, port: 10010, uuid: 00000000-0000-0000-0000-000000000003, password: secret, sni: example.com, skip-cert-verify: true}
  - {name: ssh-node, type: ssh, server: 127.0.0.1, port: 10011, username: user, password: pass}
  - name: snell-node
    type: snell
    server: 127.0.0.1
    port: 10012
    psk: secret
    version: 4
  - name: wireguard-node
    type: wireguard
    server: 162.159.192.1
    port: 2480
    ip: 172.16.0.2
    private-key: eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=
    public-key: Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=
    allowed-ips: [0.0.0.0/0]
  - {name: tailscale-node, type: tailscale, hostname: serenity-test, ephemeral: true, udp: true}
  - name: openvpn-node
    type: openvpn
    server: vpn.example.com
    port: 1194
    proto: udp
    username: user
    password: pass
    ca: |
%s
    tls-crypt: |
%s
`, indentClashFixture(openVPNTestCertificate, 6), indentClashFixture(openVPNTestTLSCrypt(), 6))

	result, err := ParseClashSubscription(context.Background(), content)
	if err != nil {
		t.Fatalf("parse full protocol fixture: %v", err)
	}
	if len(result.Outbounds) != 14 {
		t.Fatalf("expected 14 outbounds, got %d", len(result.Outbounds))
	}
	if len(result.Endpoints) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(result.Endpoints))
	}
	wantEndpointTypes := map[string]bool{C.TypeWireGuard: true, C.TypeOpenVPNClient: true, C.TypeTailscale: true}
	for _, endpoint := range result.Endpoints {
		if !wantEndpointTypes[endpoint.Type] {
			t.Fatalf("unexpected endpoint type %q", endpoint.Type)
		}
	}
	assertTargetOptionsRoundTrip(t, result)
}

func TestParseClashUnsupportedTypesAreAggregated(t *testing.T) {
	result, err := ParseClashSubscription(context.Background(), `proxies:
  - {name: valid, type: direct}
  - {name: unsupported-dns, type: dns}
  - {name: unsupported-ssr, type: ssr, server: 127.0.0.1, port: 443, cipher: aes-128-cfb, password: secret, protocol: origin, obfs: plain}
`)
	if len(result.Outbounds) != 1 || result.Outbounds[0].Type != C.TypeDirect {
		t.Fatalf("valid outbound was not preserved: %#v", result.Outbounds)
	}
	if err == nil || !strings.Contains(err.Error(), "dns") || !strings.Contains(err.Error(), "ssr") {
		t.Fatalf("expected aggregated type warnings, got %v", err)
	}
	for _, outbound := range result.Outbounds {
		if outbound.Type == "" {
			t.Fatal("parser emitted an empty outbound type")
		}
	}
}

func TestParseClashSnellECHTLS(t *testing.T) {
	echConfigPEM, _, err := boxTLS.ECHKeygenDefault("public.example.com")
	if err != nil {
		t.Fatal(err)
	}
	echBlock, _ := pem.Decode([]byte(echConfigPEM))
	if echBlock == nil {
		t.Fatal("generated ECH config is not PEM")
	}
	for _, testCase := range []struct {
		name       string
		legacyPath string
	}{
		{name: "without WebSocket path"},
		{name: "ignores legacy WebSocket path", legacyPath: "      path: /snell\n"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			content := fmt.Sprintf(`proxies:
  - name: snell-ech
    type: snell
    server: 127.0.0.1
    port: 443
    psk: secret
    version: 4
    identity: true
    obfs-opts:
      mode: ech-tls
      host: public.example.com
      sni: public.example.com
%s      ech-config: %s
      skip-cert-verify: true
      client-fingerprint: chrome
`, testCase.legacyPath, base64.StdEncoding.EncodeToString(echBlock.Bytes))
			result, err := ParseClashSubscription(context.Background(), content)
			if err != nil || len(result.Outbounds) != 1 {
				t.Fatalf("parse Snell ECH-TLS: result=%#v err=%v", result, err)
			}
			options, ok := result.Outbounds[0].Options.(*option.SnellOutboundOptions)
			if !ok || options.TLS == nil || options.TLS.ECH == nil {
				t.Fatalf("missing Snell ECH-TLS conversion: %#v", result.Outbounds[0].Options)
			}
			if len(options.TLS.ECH.Config) < 3 || options.TLS.ECH.Config[0] != "-----BEGIN ECH CONFIGS-----" || options.TLS.ECH.Config[len(options.TLS.ECH.Config)-1] != "-----END ECH CONFIGS-----" {
				t.Fatalf("ECH config was not converted to PEM lines: %#v", options.TLS.ECH.Config)
			}
			if strings.Contains(strings.Join(options.TLS.ECH.Config, ""), "\n") {
				t.Fatalf("ECH config lines should not contain embedded newlines: %#v", options.TLS.ECH.Config)
			}
			if len(options.TLS.ALPN) != 1 || options.TLS.ALPN[0] != snellECHTLSALPN {
				t.Fatalf("unexpected Snell ECH-TLS ALPN: %#v", options.TLS.ALPN)
			}
			encoded, err := json.MarshalContext(include.Context(context.Background()), &result.Outbounds[0])
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), `"transport"`) {
				t.Fatalf("Snell raw ECH-TLS should not use a transport: %s", encoded)
			}
			assertTargetOptionsRoundTrip(t, result)
		})
	}
}

func assertTargetOptionsRoundTrip(t *testing.T, result Result) {
	t.Helper()
	ctx := include.Context(context.Background())
	for _, outbound := range result.Outbounds {
		content, err := json.MarshalContext(ctx, &outbound)
		if err != nil {
			t.Fatalf("marshal outbound %s: %v", outbound.Tag, err)
		}
		var decoded option.Outbound
		if err = json.UnmarshalContext(ctx, content, &decoded); err != nil {
			t.Fatalf("unmarshal outbound %s: %v\n%s", outbound.Tag, err, content)
		}
	}
	for _, endpoint := range result.Endpoints {
		content, err := json.MarshalContext(ctx, &endpoint)
		if err != nil {
			t.Fatalf("marshal endpoint %s: %v", endpoint.Tag, err)
		}
		var decoded option.Endpoint
		if err = json.UnmarshalContext(ctx, content, &decoded); err != nil {
			t.Fatalf("unmarshal endpoint %s: %v\n%s", endpoint.Tag, err, content)
		}
	}
}

func indentClashFixture(content string, spaces int) string {
	prefix := strings.Repeat(" ", spaces)
	return prefix + strings.ReplaceAll(strings.TrimSpace(content), "\n", "\n"+prefix)
}

const openVPNTestCertificate = `-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUQbG/Z7JQGg+Jb42bBYK6q8I4g5swCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHbWlob21vMB4XDTI2MDUwMTAwMDAwMFoXDTM2MDQyOTAwMDAw
MFowEjEQMA4GA1UEAwwHbWlob21vMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
hT8O8v9COiL0e7Gmab6r8jYxgB5xIvEtL10eF6QpJm+5ROK8f8yO8JHj2L2F6i1v
g7CNgMCoX9YnZ9wqOqNTMFEwHQYDVR0OBBYEFDuK1nBI7w+Kz8o9hD7UzpJkq1N2
MB8GA1UdIwQYMBaAFDuK1nBI7w+Kz8o9hD7UzpJkq1N2MA8GA1UdEwEB/wQFMAMB
Af8wCgYIKoZIzj0EAwIDSAAwRQIhAJ4mquCRw+W1M7RCNzUVpV9qPzR9qYpK4SAi
6pEh8FeaAiBKv+YbWBjjiWk0Yxch3v7y8W7S7e3pVtHh8x9n9+6w1Q==
-----END CERTIFICATE-----`

func openVPNTestTLSCrypt() string {
	return "-----BEGIN OpenVPN Static key V1-----\n" + strings.Repeat("00", 256) + "\n-----END OpenVPN Static key V1-----"
}
