package subscription

import (
	"strings"
	"testing"

	serenityOption "github.com/sagernet/serenity/option"
	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestProcessFilterServer(t *testing.T) {
	var raw serenityOption.OutboundProcessOptions
	if err := json.Unmarshal([]byte(`{
    "filter_server": ["^selected\\.example$"],
    "rename": {"^old-": "new-"}
  }`), &raw); err != nil {
		t.Fatal(err)
	}
	process, err := NewProcessOptions(raw)
	if err != nil {
		t.Fatal(err)
	}

	outbounds := []boxOption.Outbound{
		{
			Type: C.TypeVMess,
			Tag:  "old-selected-outbound",
			Options: &boxOption.VMessOutboundOptions{
				ServerOptions: boxOption.ServerOptions{Server: "selected.example"},
			},
		},
		{
			Type: C.TypeVMess,
			Tag:  "old-other-outbound",
			Options: &boxOption.VMessOutboundOptions{
				ServerOptions: boxOption.ServerOptions{Server: "other.example"},
			},
		},
		{
			Type:    C.TypeDirect,
			Tag:     "old-no-server",
			Options: &boxOption.DirectOutboundOptions{},
		},
	}
	endpoints := []boxOption.Endpoint{
		{
			Type: C.TypeOpenVPNClient,
			Tag:  "old-selected-endpoint",
			Options: &boxOption.OpenVPNClientEndpointOptions{
				ServerOptions: boxOption.ServerOptions{Server: "selected.example"},
			},
		},
		{
			Type: C.TypeOpenVPNClient,
			Tag:  "old-other-endpoint",
			Options: &boxOption.OpenVPNClientEndpointOptions{
				ServerOptions: boxOption.ServerOptions{Server: "other.example"},
			},
		},
	}

	renameMap := process.RenameMap(outbounds, endpoints)
	if len(renameMap) != 2 || renameMap["old-selected-outbound"] != "new-selected-outbound" || renameMap["old-selected-endpoint"] != "new-selected-endpoint" {
		t.Fatalf("unexpected rename map: %#v", renameMap)
	}

	outbounds = process.Process(outbounds)
	if outbounds[0].Tag != "new-selected-outbound" {
		t.Fatalf("matching outbound was not processed: %q", outbounds[0].Tag)
	}
	if outbounds[1].Tag != "old-other-outbound" || outbounds[2].Tag != "old-no-server" {
		t.Fatalf("non-matching outbound was processed: %q, %q", outbounds[1].Tag, outbounds[2].Tag)
	}

	endpoints = process.ProcessEndpoints(endpoints)
	if endpoints[0].Tag != "new-selected-endpoint" {
		t.Fatalf("matching endpoint was not processed: %q", endpoints[0].Tag)
	}
	if endpoints[1].Tag != "old-other-endpoint" {
		t.Fatalf("non-matching endpoint was processed: %q", endpoints[1].Tag)
	}
}

func TestProcessFilterServerRejectsInvalidRegexp(t *testing.T) {
	_, err := NewProcessOptions(serenityOption.OutboundProcessOptions{
		FilterServer: []string{"["},
	})
	if err == nil || !strings.Contains(err.Error(), "parse filter_server[0]") {
		t.Fatalf("unexpected error: %v", err)
	}
}
