package subscription

import (
	"testing"

	serenityOption "github.com/sagernet/serenity/option"
	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
)

func TestProcessRewriteTLS(t *testing.T) {
	processOptions, err := NewProcessOptions(serenityOption.OutboundProcessOptions{
		RewriteTLS: &boxOption.OutboundTLSOptions{
			Enabled:    true,
			ServerName: "example.com",
			Insecure:   true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	outbounds := processOptions.Process([]boxOption.Outbound{
		{
			Type: C.TypeVMess,
			Tag:  "vmess",
			Options: &boxOption.VMessOutboundOptions{
				OutboundTLSOptionsContainer: boxOption.OutboundTLSOptionsContainer{
					TLS: &boxOption.OutboundTLSOptions{
						Enabled:    true,
						ServerName: "old.example",
					},
				},
			},
		},
		{
			Type:    C.TypeShadowsocks,
			Tag:     "shadowsocks",
			Options: &boxOption.ShadowsocksOutboundOptions{},
		},
	})

	vmessOptions := outbounds[0].Options.(*boxOption.VMessOutboundOptions)
	if vmessOptions.TLS == nil {
		t.Fatal("expected TLS options")
	}
	if !vmessOptions.TLS.Enabled {
		t.Fatal("expected TLS to be enabled")
	}
	if vmessOptions.TLS.ServerName != "example.com" {
		t.Fatalf("expected server name to be rewritten, got %q", vmessOptions.TLS.ServerName)
	}
	if !vmessOptions.TLS.Insecure {
		t.Fatal("expected insecure to be rewritten")
	}

	if _, ok := outbounds[1].Options.(*boxOption.ShadowsocksOutboundOptions); !ok {
		t.Fatalf("expected shadowsocks options to remain unchanged, got %T", outbounds[1].Options)
	}
}
