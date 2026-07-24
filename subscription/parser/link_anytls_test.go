package parser

import (
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestParseAnyTLSLink(t *testing.T) {
	outbound, err := ParseAnyTLSLink("anytls://secret@example.com:8443?sni=server.example&insecure=1&alpn=h2,http/1.1&fp=chrome&idle_session_check_interval=10s&idle-session-timeout=20s&min-idle-session=3#test-anytls")
	if err != nil {
		t.Fatal(err)
	}
	if outbound.Type != C.TypeAnyTLS {
		t.Fatalf("expected anytls outbound, got %q", outbound.Type)
	}
	if outbound.Tag != "test-anytls" {
		t.Fatalf("expected tag, got %q", outbound.Tag)
	}

	optionsValue, ok := outbound.Options.(*option.AnyTLSOutboundOptions)
	if !ok {
		t.Fatalf("expected *option.AnyTLSOutboundOptions, got %T", outbound.Options)
	}
	if optionsValue.Server != "example.com" {
		t.Fatalf("expected server, got %q", optionsValue.Server)
	}
	if optionsValue.ServerPort != 8443 {
		t.Fatalf("expected server port, got %d", optionsValue.ServerPort)
	}
	if optionsValue.Password != "secret" {
		t.Fatalf("expected password, got %q", optionsValue.Password)
	}
	if optionsValue.TLS == nil {
		t.Fatal("expected TLS options")
	}
	if !optionsValue.TLS.Enabled {
		t.Fatal("expected TLS to be enabled")
	}
	if optionsValue.TLS.ServerName != "server.example" {
		t.Fatalf("expected server name, got %q", optionsValue.TLS.ServerName)
	}
	if !optionsValue.TLS.Insecure {
		t.Fatal("expected insecure to be enabled")
	}
	if len(optionsValue.TLS.ALPN) != 2 || optionsValue.TLS.ALPN[0] != "h2" || optionsValue.TLS.ALPN[1] != "http/1.1" {
		t.Fatalf("unexpected alpn: %v", optionsValue.TLS.ALPN)
	}
	if optionsValue.TLS.UTLS == nil || optionsValue.TLS.UTLS.Fingerprint != "chrome" {
		t.Fatalf("unexpected utls: %+v", optionsValue.TLS.UTLS)
	}
	if optionsValue.IdleSessionCheckInterval.Build() != 10*time.Second {
		t.Fatalf("unexpected idle session check interval: %s", optionsValue.IdleSessionCheckInterval.Build())
	}
	if optionsValue.IdleSessionTimeout.Build() != 20*time.Second {
		t.Fatalf("unexpected idle session timeout: %s", optionsValue.IdleSessionTimeout.Build())
	}
	if optionsValue.MinIdleSession != 3 {
		t.Fatalf("expected min idle session, got %d", optionsValue.MinIdleSession)
	}
}

func TestParseSubscriptionLinkAnyTLS(t *testing.T) {
	outbound, err := ParseSubscriptionLink("anytls://secret@example.com:443#test")
	if err != nil {
		t.Fatal(err)
	}
	if outbound.Type != C.TypeAnyTLS {
		t.Fatalf("expected anytls outbound, got %q", outbound.Type)
	}
}
