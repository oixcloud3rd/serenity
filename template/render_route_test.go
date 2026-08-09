package template

import (
	"testing"

	M "github.com/sagernet/serenity/common/metadata"
	serenityOption "github.com/sagernet/serenity/option"
	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
)

func TestRenderRouteUsesPlainSniff(t *testing.T) {
	template := &Template{Template: serenityOption.Template{}}
	options := &boxOption.Options{}

	if err := template.renderRoute(M.Metadata{}, options); err != nil {
		t.Fatal(err)
	}
	sniffCount := 0
	for _, rule := range options.Route.Rules {
		if rule.DefaultOptions.Action == C.RuleActionTypeSniff {
			sniffCount++
		}
		if rule.LogicalOptions.Action == C.RuleActionTypeSniff {
			t.Fatal("expected no conditional sniff rule")
		}
	}
	if sniffCount != 1 {
		t.Fatalf("expected one plain sniff rule, got %d", sniffCount)
	}
}

func TestRenderRouteDoesNotForceResolveWithFakeIP(t *testing.T) {
	template := &Template{
		Template: serenityOption.Template{
			DisableSystemProxy: true,
			EnableFakeIP:       true,
		},
	}
	options := &boxOption.Options{}

	err := template.renderRoute(M.Metadata{}, options)
	if err != nil {
		t.Fatal(err)
	}
	if hasRouteAction(options.Route.Rules, C.RuleActionTypeResolve) {
		t.Fatal("expected no resolve route rule when system proxy is disabled")
	}
}

func TestRenderRoutePlacesStagedRules(t *testing.T) {
	template := &Template{
		Template: serenityOption.Template{
			DisableTrafficBypass: true,
			DisableClashMode:     true,
			BeforeResolveRules: []boxOption.Rule{
				routeRule("before-resolve"),
			},
			AfterResolveRules: []boxOption.Rule{
				routeRule("after-resolve"),
			},
		},
	}
	options := &boxOption.Options{}

	if err := template.renderRoute(M.Metadata{}, options); err != nil {
		t.Fatal(err)
	}

	sniffIndex := -1
	hijackDNSIndex := -1
	beforeResolveIndex := -1
	resolveIndex := -1
	afterResolveIndex := -1
	privateDirectIndex := -1
	for index, rule := range options.Route.Rules {
		action := rule.DefaultOptions.RuleAction
		if action.Action == C.RuleActionTypeSniff {
			sniffIndex = index
		}
		if rule.LogicalOptions.RuleAction.Action == C.RuleActionTypeHijackDNS {
			hijackDNSIndex = index
		}
		if action.Action == C.RuleActionTypeRoute && action.RouteOptions.Outbound == "before-resolve" {
			beforeResolveIndex = index
		}
		if action.Action == C.RuleActionTypeResolve {
			resolveIndex = index
		}
		if action.Action == C.RuleActionTypeRoute && action.RouteOptions.Outbound == "after-resolve" {
			afterResolveIndex = index
		}
		if rule.DefaultOptions.IPIsPrivate && action.Action == C.RuleActionTypeRoute && action.RouteOptions.Outbound == DefaultDirectTag {
			privateDirectIndex = index
		}
	}
	if sniffIndex == -1 || hijackDNSIndex == -1 || beforeResolveIndex == -1 || resolveIndex == -1 || afterResolveIndex == -1 || privateDirectIndex == -1 {
		t.Fatalf(
			"missing expected route rules: sniff=%d hijack_dns=%d before_resolve=%d resolve=%d after_resolve=%d private_direct=%d",
			sniffIndex,
			hijackDNSIndex,
			beforeResolveIndex,
			resolveIndex,
			afterResolveIndex,
			privateDirectIndex,
		)
	}
	if !(sniffIndex < hijackDNSIndex && hijackDNSIndex < beforeResolveIndex && beforeResolveIndex < resolveIndex && resolveIndex < afterResolveIndex && afterResolveIndex < privateDirectIndex) {
		t.Fatalf(
			"unexpected staged rule order: sniff=%d hijack_dns=%d before_resolve=%d resolve=%d after_resolve=%d private_direct=%d",
			sniffIndex,
			hijackDNSIndex,
			beforeResolveIndex,
			resolveIndex,
			afterResolveIndex,
			privateDirectIndex,
		)
	}
}

func routeRule(outbound string) boxOption.Rule {
	return boxOption.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: boxOption.DefaultRule{
			RuleAction: boxOption.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: boxOption.RouteActionOptions{
					Outbound: outbound,
				},
			},
		},
	}
}

func hasRouteAction(rules []boxOption.Rule, action string) bool {
	for _, rule := range rules {
		if rule.DefaultOptions.Action == action || rule.LogicalOptions.Action == action {
			return true
		}
	}
	return false
}
