package template

import (
	"testing"

	M "github.com/sagernet/serenity/common/metadata"
	"github.com/sagernet/serenity/common/semver"
	serenityOption "github.com/sagernet/serenity/option"
	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

func TestRenderGeoResourcesHTTPClients(t *testing.T) {
	template := &Template{}
	options := &boxOption.Options{
		Route: &boxOption.RouteOptions{},
	}

	template.renderGeoResources(M.Metadata{
		Version: common.Ptr(semver.ParseVersion("1.14.0-alpha.13")),
	}, options)

	if len(options.HTTPClients) != 1 {
		t.Fatalf("expected default http client, got %d", len(options.HTTPClients))
	}
	if options.HTTPClients[0].Tag != DefaultHTTPClientTag {
		t.Fatalf("expected default http client tag %q, got %q", DefaultHTTPClientTag, options.HTTPClients[0].Tag)
	}
	if options.HTTPClients[0].DialerOptions.Detour != DefaultDefaultTag {
		t.Fatalf("expected default http client detour %q, got %q", DefaultDefaultTag, options.HTTPClients[0].DialerOptions.Detour)
	}
	if options.Route.DefaultHTTPClient != DefaultHTTPClientTag {
		t.Fatalf("expected route default http client %q, got %q", DefaultHTTPClientTag, options.Route.DefaultHTTPClient)
	}
	for _, ruleSet := range options.Route.RuleSet {
		if ruleSet.RemoteOptions.DownloadDetour != "" {
			t.Fatalf("expected no legacy download_detour, got %q", ruleSet.RemoteOptions.DownloadDetour)
		}
	}
}

func TestRenderGeoResourcesLegacyDownloadDetour(t *testing.T) {
	template := &Template{}
	template.EnableJSDelivr = true
	options := &boxOption.Options{
		Route: &boxOption.RouteOptions{},
	}

	template.renderGeoResources(M.Metadata{
		Version: common.Ptr(semver.ParseVersion("1.13.0")),
	}, options)

	if len(options.HTTPClients) != 0 {
		t.Fatalf("expected no http clients for legacy version, got %d", len(options.HTTPClients))
	}
	if options.Route.DefaultHTTPClient != "" {
		t.Fatalf("expected no default http client for legacy version, got %q", options.Route.DefaultHTTPClient)
	}
	for _, ruleSet := range options.Route.RuleSet {
		if ruleSet.RemoteOptions.DownloadDetour != DefaultDirectTag {
			t.Fatalf("expected legacy download_detour %q, got %q", DefaultDirectTag, ruleSet.RemoteOptions.DownloadDetour)
		}
	}
}

func TestRenderRuleSetMigratesDownloadDetourToHTTPClient(t *testing.T) {
	template := &Template{}
	ruleSets := template.renderRuleSet(M.Metadata{
		Version: common.Ptr(semver.ParseVersion("1.14.0-alpha.13")),
	}, []serenityOption.RuleSet{
		{
			Type: C.RuleSetTypeRemote,
			DefaultOptions: boxOption.RuleSet{
				Type:   C.RuleSetTypeRemote,
				Tag:    []string{"remote"},
				Format: C.RuleSetFormatBinary,
				RemoteOptions: boxOption.RemoteRuleSet{
					URL:            "https://example.com/rule-set.srs",
					DownloadDetour: DefaultDirectTag,
				},
			},
		},
	})

	if len(ruleSets) != 1 {
		t.Fatalf("expected one rule set, got %d", len(ruleSets))
	}
	if ruleSets[0].RemoteOptions.DownloadDetour != "" {
		t.Fatalf("expected legacy download_detour to be removed, got %q", ruleSets[0].RemoteOptions.DownloadDetour)
	}
	if ruleSets[0].RemoteOptions.HTTPClient == nil {
		t.Fatal("expected http_client")
	}
	if ruleSets[0].RemoteOptions.HTTPClient.DialerOptions.Detour != DefaultDirectTag {
		t.Fatalf("expected http_client detour %q, got %q", DefaultDirectTag, ruleSets[0].RemoteOptions.HTTPClient.DialerOptions.Detour)
	}
}
