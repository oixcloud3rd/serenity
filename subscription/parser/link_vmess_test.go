package parser

import (
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestParseVmessLinkBase64Insecure(t *testing.T) {
	payload := []byte(`{
		"v": "2",
		"ps": "test-vmess",
		"add": "example.com",
		"port": "443",
		"id": "00000000-0000-0000-0000-000000000000",
		"aid": "0",
		"net": "tcp",
		"tls": "tls",
		"sni": "server.example",
		"scy": "auto",
		"insecure": true
	}`)

	outbound, err := ParseVmessLink("vmess://" + base64.StdEncoding.EncodeToString(payload))
	if err != nil {
		t.Fatal(err)
	}

	tlsOptions := vmessTLSOptions(t, outbound.Options)
	if !tlsOptions.Insecure {
		t.Fatal("expected insecure to be enabled")
	}
}

func TestParseVmessLinkURLInsecure(t *testing.T) {
	outbound, err := ParseVmessLink("vmess://00000000-0000-0000-0000-000000000000@example.com:443?tls=tls&insecure=1")
	if err != nil {
		t.Fatal(err)
	}

	tlsOptions := vmessTLSOptions(t, outbound.Options)
	if !tlsOptions.Insecure {
		t.Fatal("expected insecure to be enabled")
	}
}

func vmessTLSOptions(t *testing.T, optionsValue any) *option.OutboundTLSOptions {
	t.Helper()

	vmessOptions, ok := optionsValue.(*option.VMessOutboundOptions)
	if !ok {
		t.Fatalf("expected *option.VMessOutboundOptions, got %T", optionsValue)
	}
	if vmessOptions.TLS == nil {
		t.Fatal("expected TLS options")
	}

	return vmessOptions.TLS
}
