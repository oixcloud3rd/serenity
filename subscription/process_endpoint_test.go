package subscription

import (
	"testing"

	serenityOption "github.com/sagernet/serenity/option"
	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestProcessOptionsApplyTagOperationsToEndpointsOnly(t *testing.T) {
	var raw serenityOption.OutboundProcessOptions
	if err := json.Unmarshal([]byte(`{
    "filter_type": ["tailscale"],
    "rename": {"^old-": "new-"},
    "remove_emoji": true,
    "rewrite_tls": {"enabled": true}
  }`), &raw); err != nil {
		t.Fatal(err)
	}
	process, err := NewProcessOptions(raw)
	if err != nil {
		t.Fatal(err)
	}
	endpoints := process.ProcessEndpoints([]boxOption.Endpoint{
		{Type: C.TypeTailscale, Tag: "old-tail🚀net", Options: &boxOption.TailscaleEndpointOptions{}},
		{Type: C.TypeWireGuard, Tag: "old-wireguard", Options: &boxOption.WireGuardEndpointOptions{}},
	})
	if endpoints[0].Tag != "new-tailnet" {
		t.Fatalf("endpoint rename/emoji removal failed: %q", endpoints[0].Tag)
	}
	if endpoints[1].Tag != "old-wireguard" {
		t.Fatalf("non-matching endpoint was modified: %q", endpoints[1].Tag)
	}
}
