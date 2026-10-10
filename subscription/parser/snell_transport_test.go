package parser

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestParseClashSnellTransport(t *testing.T) {
	echConfig := testECHConfigBase64(t)
	for _, transport := range []string{"", "tcp", "h3", "auto"} {
		t.Run("transport="+transport, func(t *testing.T) {
			content := fmt.Sprintf(`proxies:
  - name: snell-test
    type: snell
    server: 127.0.0.1
    port: 443
    psk: test-password
    version: 4
    identity: true
    reuse: true
    udp: true
    tfo: true
    obfs-opts:
      mode: ech-tls
      transport: %q
      alpn: snell-ech/1
      identity-version: 2
      legacy-fallback: false
      preconnect: 2
      path: /legacy-path
      sni: public.example.com
      ech-config: %s
      skip-cert-verify: false
`, transport, echConfig)
			result, err := ParseClashSubscription(context.Background(), content)
			if err != nil || len(result.Outbounds) != 1 {
				t.Fatalf("parse Snell transport: count=%d err=%v", len(result.Outbounds), err)
			}
			target := result.Outbounds[0].Options.(*option.SnellOutboundOptions)
			if transport == "" || transport == "tcp" {
				if target.Transport != nil {
					t.Fatal("TCP must not emit a transport")
				}
			} else {
				want := &option.SnellTransportOptions{
					Type: "http3", Fallback: transport == "auto", QUICCongestionControl: "reno",
				}
				if !reflect.DeepEqual(target.Transport, want) {
					t.Fatalf("transport=%#v, want %#v", target.Transport, want)
				}
			}
			if target.Version != 4 || target.Identity == nil || *target.Identity != 2 ||
				!target.Reuse || target.Preconnect != 2 || !target.TCPFastOpen ||
				string(target.Network) != "" || target.Server != "127.0.0.1" ||
				target.ServerPort != 443 || target.PSK != "test-password" {
				t.Fatal("Snell or dialer fields were lost")
			}
			ctx := include.Context(context.Background())
			encoded, err := json.MarshalContext(ctx, &result.Outbounds[0])
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "legacy-path") {
				t.Fatal("legacy path must not be emitted")
			}
			var decoded option.Outbound
			if err = json.UnmarshalContext(ctx, encoded, &decoded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded.Options, target) {
				t.Fatal("Snell options changed during JSON round trip")
			}
		})
	}
}

func TestParseBoxSnellTransportPreservesExplicitOptions(t *testing.T) {
	ctx := include.Context(context.Background())
	for _, algorithm := range []string{"reno", "bbr"} {
		t.Run("algorithm="+algorithm, func(t *testing.T) {
			profile := ""
			if algorithm == "bbr" {
				profile = `,"bbr_profile":"aggressive"`
			}
			content := fmt.Sprintf(`{"outbounds":[{
				"type":"snell","tag":"native","version":4,
				"server":"127.0.0.1","server_port":443,"psk":"test-password","identity":2,
				"transport":{"type":"http3","fallback":true,"quic_congestion_control":%q%s},
				"tls":{"enabled":true,"server_name":"public.example.com","ech":{"enabled":true}}
			}]}`, algorithm, profile)
			result, err := ParseSubscription(ctx, content)
			if err != nil || len(result.Outbounds) != 1 {
				t.Fatalf("parse native transport: count=%d err=%v", len(result.Outbounds), err)
			}
			transport := result.Outbounds[0].Options.(*option.SnellOutboundOptions).Transport
			if transport == nil || transport.Type != "http3" || !transport.Fallback ||
				transport.QUICCongestionControl != algorithm {
				t.Fatalf("native transport was changed: %#v", transport)
			}
			if algorithm == "bbr" && (transport.BBRProfile == nil || *transport.BBRProfile != "aggressive") {
				t.Fatal("explicit BBR profile was lost")
			}
			assertTargetOptionsRoundTrip(t, result)
		})
	}
}
