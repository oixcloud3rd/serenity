package subscription

import (
	"reflect"
	"testing"

	serenityOption "github.com/sagernet/serenity/option"
	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
)

func TestProcessRewriteSnellTransport(t *testing.T) {
	for _, test := range []struct {
		name    string
		rewrite string
		wantCC  string
		profile *string
	}{
		{"unchanged", `{}`, "bbr", common.Ptr("aggressive")},
		{"reno clears profile", `{"rewrite_quic_congestion_control":"reno"}`, "reno", nil},
		{"cubic clears profile", `{"rewrite_quic_congestion_control":"cubic"}`, "cubic", nil},
		{"bbr keeps profile", `{"rewrite_quic_congestion_control":"bbr"}`, "bbr", common.Ptr("aggressive")},
		{"standard", `{"rewrite_quic_congestion_control":"bbr","rewrite_bbr_profile":"standard"}`, "bbr", common.Ptr("standard")},
		{"conservative", `{"rewrite_quic_congestion_control":"bbr","rewrite_bbr_profile":"conservative"}`, "bbr", common.Ptr("conservative")},
		{"clear profile", `{"rewrite_bbr_profile":""}`, "bbr", nil},
		{"null unchanged", `{"rewrite_bbr_profile":null}`, "bbr", common.Ptr("aggressive")},
	} {
		t.Run(test.name, func(t *testing.T) {
			var raw serenityOption.OutboundProcessOptions
			if err := json.Unmarshal([]byte(test.rewrite), &raw); err != nil {
				t.Fatal(err)
			}
			raw.Filter = []string{"^selected$"}
			process, err := NewProcessOptions(raw)
			if err != nil {
				t.Fatal(err)
			}
			original := &boxOption.SnellOutboundOptions{
				AbstractSnellOutboundOptions: boxOption.AbstractSnellOutboundOptions{
					Transport: &boxOption.SnellTransportOptions{
						Type: "http3", HappyEyeballs: true, QUICCongestionControl: "bbr", BBRProfile: common.Ptr("aggressive"),
					},
				},
			}
			tcp := &boxOption.SnellOutboundOptions{}
			tuic := &boxOption.TUICOutboundOptions{CongestionControl: "cubic"}
			source := []boxOption.Outbound{
				{Type: C.TypeSnell, Tag: "selected", Options: original},
				{Type: C.TypeSnell, Tag: "unmatched", Options: original},
				{Type: C.TypeSnell, Tag: "selected", Options: tcp},
				{Type: C.TypeTUIC, Tag: "selected", Options: tuic},
			}
			result := process.Process(source)
			transport := result[0].Options.(*boxOption.SnellOutboundOptions).Transport
			if transport.Type != "http3" || !transport.HappyEyeballs || transport.QUICCongestionControl != test.wantCC ||
				!reflect.DeepEqual(transport.BBRProfile, test.profile) {
				t.Fatalf("unexpected rewritten transport: %#v", transport)
			}
			if err := transport.Validate(); err != nil {
				t.Fatalf("rewrite generated an invalid transport: %v", err)
			}
			if original.Transport.QUICCongestionControl != "bbr" || *original.Transport.BBRProfile != "aggressive" {
				t.Fatal("source transport was mutated")
			}
			if result[1].Options != original || result[2].Options != tcp || result[3].Options != tuic {
				t.Fatal("unmatched or non-H3 outbound was changed")
			}
		})
	}
}

func TestProcessRejectsInvalidSnellTransportRewrite(t *testing.T) {
	for _, content := range []string{
		`{"rewrite_quic_congestion_control":"unknown"}`,
		`{"rewrite_bbr_profile":"aggressive"}`,
		`{"rewrite_quic_congestion_control":"reno","rewrite_bbr_profile":"standard"}`,
		`{"rewrite_quic_congestion_control":"cubic","rewrite_bbr_profile":"conservative"}`,
		`{"rewrite_quic_congestion_control":"bbr","rewrite_bbr_profile":"unknown"}`,
	} {
		t.Run(content, func(t *testing.T) {
			var raw serenityOption.OutboundProcessOptions
			if err := json.Unmarshal([]byte(content), &raw); err != nil {
				t.Fatal(err)
			}
			if _, err := NewProcessOptions(raw); err == nil {
				t.Fatal("invalid rewrite was accepted")
			}
		})
	}
}
