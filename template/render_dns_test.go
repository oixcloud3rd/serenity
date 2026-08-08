package template

import (
	"context"
	"testing"

	M "github.com/sagernet/serenity/common/metadata"
	"github.com/sagernet/serenity/common/semver"
	serenityOption "github.com/sagernet/serenity/option"
	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"

	mDNS "github.com/miekg/dns"
)

func TestRenderDNSFakeIPRulesWithDefaultRules(t *testing.T) {
	template := &Template{
		Template: serenityOption.Template{
			EnableFakeIP: true,
		},
	}
	options := &boxOption.Options{}

	err := template.renderDNS(context.Background(), M.Metadata{}, options)
	if err != nil {
		t.Fatal(err)
	}

	globalFakeIPRuleIndex := -1
	globalRuleIndex := -1
	chinaRuleIndex := -1
	ruleFakeIPRuleIndex := -1
	ruleRuleIndex := -1
	foreignFakeIPRuleIndex := -1
	foreignRuleIndex := -1
	evaluateRuleIndex := -1
	matchResponseRuleIndex := -1
	fallbackRuleIndex := -1
	for index, rule := range options.DNS.Rules {
		if rule.DefaultOptions.RouteOptions.Server == DNSFakeIPTag && rule.DefaultOptions.ClashMode == "Global" {
			globalFakeIPRuleIndex = index
			assertFakeIPDNSRule(t, rule)
		}
		if rule.DefaultOptions.ClashMode == "Global" {
			globalRuleIndex = index
		}
		if len(rule.DefaultOptions.RuleSet) == 1 && rule.DefaultOptions.RuleSet[0] == "geosite-geolocation-cn" {
			chinaRuleIndex = index
		}
		if rule.DefaultOptions.RouteOptions.Server == DNSFakeIPTag && rule.DefaultOptions.ClashMode == "Rule" {
			ruleFakeIPRuleIndex = index
			assertFakeIPDNSRule(t, rule)
		}
		if rule.DefaultOptions.ClashMode == "Rule" && rule.DefaultOptions.RouteOptions.Server == DNSDefaultTag {
			ruleRuleIndex = index
		}
		if rule.DefaultOptions.RouteOptions.Server == DNSFakeIPTag &&
			len(rule.DefaultOptions.RuleSet) == 1 &&
			rule.DefaultOptions.RuleSet[0] == "geosite-geolocation-!cn" {
			foreignFakeIPRuleIndex = index
			assertFakeIPDNSRule(t, rule)
		}
		if rule.DefaultOptions.RouteOptions.Server == DNSDefaultTag &&
			len(rule.DefaultOptions.RuleSet) == 1 &&
			rule.DefaultOptions.RuleSet[0] == "geosite-geolocation-!cn" {
			foreignRuleIndex = index
		}
		if rule.DefaultOptions.Action == C.RuleActionTypeEvaluate {
			if rule.DefaultOptions.EvaluateOptions.Server != DNSLocalTag {
				t.Fatalf("expected evaluate DNS rule server %q, got %q", DNSLocalTag, rule.DefaultOptions.EvaluateOptions.Server)
			}
			evaluateRuleIndex = index
		}
		if rule.DefaultOptions.MatchResponse.IsEnabled() {
			matchResponseRuleIndex = index
		}
		if rule.DefaultOptions.Action == C.RuleActionTypeRoute &&
			rule.DefaultOptions.RouteOptions.Server == DNSFakeIPTag &&
			rule.DefaultOptions.ClashMode == "" &&
			len(rule.DefaultOptions.RuleSet) == 0 {
			fallbackRuleIndex = index
			assertFakeIPDNSRule(t, rule)
		}
	}
	if globalFakeIPRuleIndex == -1 {
		t.Fatal("expected Global FakeIP DNS rule")
	}
	if globalRuleIndex == -1 {
		t.Fatal("expected Global clash mode DNS rule")
	}
	if chinaRuleIndex == -1 {
		t.Fatal("expected geosite-geolocation-cn DNS rule")
	}
	if ruleFakeIPRuleIndex == -1 {
		t.Fatal("expected Rule FakeIP DNS rule")
	}
	if ruleRuleIndex == -1 {
		t.Fatal("expected Rule DNS rule")
	}
	if foreignFakeIPRuleIndex == -1 {
		t.Fatal("expected geosite-geolocation-!cn FakeIP DNS rule")
	}
	if foreignRuleIndex == -1 {
		t.Fatal("expected geosite-geolocation-!cn DNS rule")
	}
	if evaluateRuleIndex == -1 {
		t.Fatal("expected evaluate DNS rule")
	}
	if matchResponseRuleIndex == -1 {
		t.Fatal("expected match_response DNS rule")
	}
	if fallbackRuleIndex == -1 {
		t.Fatal("expected FakeIP fallback DNS rule")
	}
	if globalFakeIPRuleIndex > globalRuleIndex {
		t.Fatalf("expected Global FakeIP DNS rule before Global DNS rule, got %d > %d", globalFakeIPRuleIndex, globalRuleIndex)
	}
	if !(chinaRuleIndex < ruleFakeIPRuleIndex &&
		ruleFakeIPRuleIndex < ruleRuleIndex &&
		ruleRuleIndex < foreignFakeIPRuleIndex &&
		foreignFakeIPRuleIndex < foreignRuleIndex &&
		foreignRuleIndex < evaluateRuleIndex &&
		evaluateRuleIndex < matchResponseRuleIndex &&
		matchResponseRuleIndex < fallbackRuleIndex) {
		t.Fatalf("unexpected Rule DNS order: cn=%d, rule_fakeip=%d, rule=%d, foreign_fakeip=%d, foreign=%d, evaluate=%d, match_response=%d, fallback=%d",
			chinaRuleIndex, ruleFakeIPRuleIndex, ruleRuleIndex, foreignFakeIPRuleIndex, foreignRuleIndex, evaluateRuleIndex, matchResponseRuleIndex, fallbackRuleIndex)
	}
}

func TestRenderDNSDoesNotGenerateFakeIPWhenDisabled(t *testing.T) {
	template := &Template{}
	options := &boxOption.Options{}

	err := template.renderDNS(context.Background(), M.Metadata{}, options)
	if err != nil {
		t.Fatal(err)
	}

	for _, server := range options.DNS.Servers {
		if server.Tag == DNSFakeIPTag {
			t.Fatal("unexpected FakeIP DNS server when FakeIP is disabled")
		}
	}
	for _, rule := range options.DNS.Rules {
		if rule.DefaultOptions.RouteOptions.Server == DNSFakeIPTag {
			t.Fatal("unexpected DNS rule routed to FakeIP when FakeIP is disabled")
		}
	}
}

func TestRenderDNSDomainResolvers(t *testing.T) {
	tests := []struct {
		name                string
		defaultDNS          string
		localDNS            string
		enableLocalSetup    bool
		expectedLocalSetup  bool
		expectedLocalServer string
	}{
		{
			name:       "local IP URL",
			defaultDNS: "tls://dns.google",
			localDNS:   "https://223.5.5.5/dns-query",
		},
		{
			name:                "local domain URL",
			defaultDNS:          "tls://dns.google",
			localDNS:            "https://dns.alidns.com/dns-query",
			expectedLocalSetup:  true,
			expectedLocalServer: DNSLocalSetupTag,
		},
		{
			name:                "bare domain names",
			defaultDNS:          "dns.google",
			localDNS:            "dns.alidns.com",
			expectedLocalSetup:  true,
			expectedLocalServer: DNSLocalSetupTag,
		},
		{
			name:       "system resolver",
			defaultDNS: "tls://dns.google",
			localDNS:   "local",
		},
		{
			name:               "forced local setup with IP URL",
			defaultDNS:         "tls://dns.google",
			localDNS:           "https://223.5.5.5/dns-query",
			enableLocalSetup:   true,
			expectedLocalSetup: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			template := &Template{
				Template: serenityOption.Template{
					DNS:              test.defaultDNS,
					DNSLocal:         test.localDNS,
					EnableLocalSetup: test.enableLocalSetup,
				},
			}
			var options boxOption.Options
			if err := template.renderDNS(context.Background(), M.Metadata{}, &options); err != nil {
				t.Fatal(err)
			}

			defaultServer := findDNSServer(t, options.DNS.Servers, DNSDefaultTag)
			if resolver := dnsServerDomainResolver(defaultServer); resolver != "" {
				t.Fatalf("expected default DNS resolver to be unset, got %q", resolver)
			}
			localServer := findDNSServer(t, options.DNS.Servers, DNSLocalTag)
			if resolver := dnsServerDomainResolver(localServer); resolver != test.expectedLocalServer {
				t.Fatalf("expected local DNS resolver %q, got %q", test.expectedLocalServer, resolver)
			}
			localSetupFound := false
			for _, server := range options.DNS.Servers {
				if server.Tag == DNSLocalSetupTag {
					localSetupFound = true
					break
				}
			}
			if localSetupFound != test.expectedLocalSetup {
				t.Fatalf("expected local_setup presence %t, got %t", test.expectedLocalSetup, localSetupFound)
			}
		})
	}
}

func findDNSServer(t *testing.T, servers []boxOption.DNSServerOptions, tag string) *boxOption.DNSServerOptions {
	t.Helper()
	for index := range servers {
		if servers[index].Tag == tag {
			return &servers[index]
		}
	}
	t.Fatalf("DNS server %q not found", tag)
	return nil
}

func dnsServerDomainResolver(server *boxOption.DNSServerOptions) string {
	var resolver *boxOption.DomainResolveOptions
	switch options := server.Options.(type) {
	case *boxOption.LocalDNSServerOptions:
		resolver = options.DialerOptions.DomainResolver
	case *boxOption.RemoteDNSServerOptions:
		resolver = options.DialerOptions.DomainResolver
	case *boxOption.RemoteTLSDNSServerOptions:
		resolver = options.DialerOptions.DomainResolver
	case *boxOption.RemoteHTTPSDNSServerOptions:
		resolver = options.DialerOptions.DomainResolver
	}
	if resolver == nil {
		return ""
	}
	return resolver.Server
}

func assertFakeIPDNSRule(t *testing.T, rule boxOption.DNSRule) {
	t.Helper()

	if len(rule.DefaultOptions.QueryType) != 2 {
		t.Fatalf("expected A and AAAA query types, got %d", len(rule.DefaultOptions.QueryType))
	}
	if rule.DefaultOptions.QueryType[0] != boxOption.DNSQueryType(mDNS.TypeA) {
		t.Fatalf("expected first query type A, got %q", rule.DefaultOptions.QueryType[0])
	}
	if rule.DefaultOptions.QueryType[1] != boxOption.DNSQueryType(mDNS.TypeAAAA) {
		t.Fatalf("expected second query type AAAA, got %q", rule.DefaultOptions.QueryType[1])
	}
	if rule.DefaultOptions.RouteOptions.RewriteTTL != nil {
		t.Fatalf("expected no rewrite_ttl by default, got %d", *rule.DefaultOptions.RouteOptions.RewriteTTL)
	}
}

func TestRenderDNSIndependentCacheCompatibility(t *testing.T) {
	template := &Template{
		Template: serenityOption.Template{
			EnableFakeIP: true,
		},
	}

	var latestOptions boxOption.Options
	err := template.renderDNS(context.Background(), M.Metadata{}, &latestOptions)
	if err != nil {
		t.Fatal(err)
	}
	if latestOptions.DNS.DNSClientOptions.IndependentCache {
		t.Fatal("expected no deprecated independent_cache for latest sing-box")
	}

	var legacyOptions boxOption.Options
	err = template.renderDNS(context.Background(), M.Metadata{
		Version: common.Ptr(semver.ParseVersion("1.13.0")),
	}, &legacyOptions)
	if err != nil {
		t.Fatal(err)
	}
	if !legacyOptions.DNS.DNSClientOptions.IndependentCache {
		t.Fatal("expected independent_cache for legacy sing-box")
	}
}

func TestRenderDNSFakeIPRewriteTTL(t *testing.T) {
	template := &Template{
		Template: serenityOption.Template{
			EnableFakeIP:     true,
			FakeIPRewriteTTL: common.Ptr(uint32(0)),
		},
	}
	var options boxOption.Options
	err := template.renderDNS(context.Background(), M.Metadata{}, &options)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range options.DNS.Rules {
		if rule.DefaultOptions.RouteOptions.Server != DNSFakeIPTag {
			continue
		}
		if rule.DefaultOptions.RouteOptions.RewriteTTL == nil {
			t.Fatal("expected rewrite_ttl")
		}
		if *rule.DefaultOptions.RouteOptions.RewriteTTL != 0 {
			t.Fatalf("expected rewrite_ttl 0, got %d", *rule.DefaultOptions.RouteOptions.RewriteTTL)
		}
		return
	}
	t.Fatal("expected FakeIP DNS rule")
}

func TestRenderDNSInheritFakeIPRewriteTTL(t *testing.T) {
	explicitRewriteTTL := uint32(60)
	template := &Template{
		Template: serenityOption.Template{
			FakeIPRewriteTTL:        common.Ptr(uint32(0)),
			InheritFakeIPRewriteTTL: true,
			StartDNSRules: []boxOption.DNSRule{
				customDNSRouteRule(DNSFakeIPTag, nil),
				customDNSRouteRule(DNSFakeIPTag, &explicitRewriteTTL),
				customDNSRouteRule(DNSDefaultTag, nil),
				{
					Type: C.RuleTypeLogical,
					LogicalOptions: boxOption.LogicalDNSRule{
						RawLogicalDNSRule: boxOption.RawLogicalDNSRule{
							Mode: C.LogicalTypeAnd,
							Rules: []boxOption.DNSRule{
								customDNSRouteRule(DNSFakeIPTag, nil),
							},
						},
					},
				},
			},
		},
	}
	var options boxOption.Options
	err := template.renderDNS(context.Background(), M.Metadata{}, &options)
	if err != nil {
		t.Fatal(err)
	}
	if options.DNS.Rules[0].DefaultOptions.RouteOptions.RewriteTTL == nil {
		t.Fatal("expected inherited rewrite_ttl")
	}
	if *options.DNS.Rules[0].DefaultOptions.RouteOptions.RewriteTTL != 0 {
		t.Fatalf("expected inherited rewrite_ttl 0, got %d", *options.DNS.Rules[0].DefaultOptions.RouteOptions.RewriteTTL)
	}
	if options.DNS.Rules[1].DefaultOptions.RouteOptions.RewriteTTL == nil || *options.DNS.Rules[1].DefaultOptions.RouteOptions.RewriteTTL != explicitRewriteTTL {
		t.Fatal("expected explicit rewrite_ttl to be preserved")
	}
	if options.DNS.Rules[2].DefaultOptions.RouteOptions.RewriteTTL != nil {
		t.Fatal("expected non-FakeIP server rule to be untouched")
	}
	if options.DNS.Rules[3].LogicalOptions.Rules[0].DefaultOptions.RouteOptions.RewriteTTL != nil {
		t.Fatal("expected nested logical DNS rule to be untouched")
	}
	if template.StartDNSRules[0].DefaultOptions.RouteOptions.RewriteTTL != nil {
		t.Fatal("expected original template rules to remain unmodified")
	}
}

func TestRenderDNSDoesNotInheritFakeIPRewriteTTLByDefault(t *testing.T) {
	template := &Template{
		Template: serenityOption.Template{
			FakeIPRewriteTTL: common.Ptr(uint32(0)),
			StartDNSRules: []boxOption.DNSRule{
				customDNSRouteRule(DNSFakeIPTag, nil),
			},
		},
	}
	var options boxOption.Options
	err := template.renderDNS(context.Background(), M.Metadata{}, &options)
	if err != nil {
		t.Fatal(err)
	}
	if options.DNS.Rules[0].DefaultOptions.RouteOptions.RewriteTTL != nil {
		t.Fatal("expected user DNS rule to remain unchanged by default")
	}
}

func customDNSRouteRule(server string, rewriteTTL *uint32) boxOption.DNSRule {
	return boxOption.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: boxOption.DefaultDNSRule{
			DNSRuleAction: boxOption.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: boxOption.DNSRouteActionOptions{
					Server: server,
					AbstractDNSRouteActionOptions: boxOption.AbstractDNSRouteActionOptions{
						RewriteTTL: rewriteTTL,
					},
				},
			},
		},
	}
}
