package template

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"reflect"
	"testing"

	"github.com/sagernet/serenity/common/cachefile"
	M "github.com/sagernet/serenity/common/metadata"
	serenityOption "github.com/sagernet/serenity/option"
	"github.com/sagernet/serenity/subscription"
	"github.com/sagernet/serenity/subscription/parser"
	boxTLS "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/include"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
)

func TestSnellTransportSubscriptionCacheAndExport(t *testing.T) {
	ctx := include.Context(context.Background())
	config, _, err := boxTLS.ECHKeygenDefault("public.example.com")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(config))
	if block == nil {
		t.Fatal("invalid generated ECH config")
	}
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
      transport: auto
      preconnect: 2
      sni: public.example.com
      ech-config: %s
`, base64.StdEncoding.EncodeToString(block.Bytes))
	parsed, err := parser.ParseSubscription(ctx, content)
	if err != nil || len(parsed.Outbounds) != 1 {
		t.Fatalf("parse fixture: count=%d err=%v", len(parsed.Outbounds), err)
	}
	original := &cachefile.Subscription{Content: parsed.Outbounds}
	data, err := original.MarshalBinary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var saved cachefile.Subscription
	if err = saved.UnmarshalBinary(ctx, data); err != nil || !reflect.DeepEqual(saved.Content, parsed.Outbounds) {
		t.Fatalf("cache did not preserve Snell fields: %v", err)
	}
	process, err := subscription.NewProcessOptions(serenityOption.OutboundProcessOptions{
		RewriteQUICCongestionControl: "bbr", RewriteBBRProfile: common.Ptr("conservative"),
	})
	if err != nil {
		t.Fatal(err)
	}
	servers := process.Process(saved.Content)
	template := &Template{Template: serenityOption.Template{
		DisableTUN: true, DisableTrafficBypass: true, DisableDefaultRules: true,
	}}
	output, err := template.Render(ctx, M.Metadata{}, "test", nil, nil, []*subscription.Subscription{{
		Subscription: serenityOption.Subscription{Name: "managed"},
		Servers:      servers,
	}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalContext(ctx, output)
	if err != nil {
		t.Fatal(err)
	}
	var decoded boxOption.Options
	if err = json.UnmarshalContext(ctx, encoded, &decoded); err != nil {
		t.Fatalf("export failed target validation: %v", err)
	}
	outbound := findTestOutbound(decoded.Outbounds, "snell-test")
	if outbound == nil || !reflect.DeepEqual(outbound.Options, servers[0].Options) {
		t.Fatal("export did not preserve processed Snell options")
	}
	target := outbound.Options.(*boxOption.SnellOutboundOptions)
	if target.Transport == nil || !target.Transport.HappyEyeballs ||
		target.Transport.QUICCongestionControl != "bbr" ||
		target.Transport.BBRProfile == nil || *target.Transport.BBRProfile != "conservative" {
		t.Fatal("export lost transport rewrite")
	}
	if !reflect.DeepEqual(saved.Content, parsed.Outbounds) {
		t.Fatal("processing or rendering changed the source cache")
	}
}
