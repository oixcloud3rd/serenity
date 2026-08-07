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

func TestRenderRouteOverrideAddressWithDomain(t *testing.T) {
	defaultMode := boxOption.RouteOverrideAddressWithDomain(C.RouteOverrideAddressWithDomainIfResolvable)
	directMode := boxOption.RouteOverrideAddressWithDomain(C.RouteOverrideAddressWithDomainDisable)
	template := &Template{Template: serenityOption.Template{
		DisableTrafficBypass:                 true,
		DisableSystemProxy:                   true,
		DisableClashMode:                     true,
		DisableDefaultRules:                  true,
		DirectTag:                            "direct-out",
		DefaultTag:                           "proxy-out",
		RouteOverrideAddressWithDomain:       defaultMode,
		RouteOverrideAddressWithDomainDirect: directMode,
		StartRules: []boxOption.Rule{
			routeRuleWithOverride("proxy-out", C.RouteOverrideAddressWithDomainDisable),
			routeRuleWithOverride("direct-out", C.RouteOverrideAddressWithDomainAlways),
			{
				Type: C.RuleTypeLogical,
				LogicalOptions: boxOption.LogicalRule{
					RawLogicalRule: boxOption.RawLogicalRule{
						Mode: C.LogicalTypeOr,
						Rules: []boxOption.Rule{
							routeRuleWithOverride("nested-proxy", C.RouteOverrideAddressWithDomainAlways),
						},
					},
				},
			},
		},
	}}
	options := &boxOption.Options{}

	if err := template.renderRoute(M.Metadata{}, options); err != nil {
		t.Fatal(err)
	}
	if actual := finalRouteOverrideAddressWithDomain(options.Route.Rules); actual != defaultMode {
		t.Fatalf("expected final override mode %q, got %q", defaultMode, actual)
	}
	assertRouteOverrideAddressWithDomain(t, options.Route.Rules, "direct-out", defaultMode, directMode)
}

func TestRenderRouteOverrideAddressWithDomainPreservesExistingValuesByDefault(t *testing.T) {
	template := &Template{Template: serenityOption.Template{
		DisableTrafficBypass: true,
		DisableSystemProxy:   true,
		DisableClashMode:     true,
		StartRules: []boxOption.Rule{
			routeRuleWithOverride("proxy", C.RouteOverrideAddressWithDomainAlways),
		},
	}}
	options := &boxOption.Options{}

	if err := template.renderRoute(M.Metadata{}, options); err != nil {
		t.Fatal(err)
	}
	actual := options.Route.Rules[0].DefaultOptions.RouteOptions.OverrideAddressWithDomain
	if actual != boxOption.RouteOverrideAddressWithDomain(C.RouteOverrideAddressWithDomainAlways) {
		t.Fatalf("expected existing override mode to be preserved, got %q", actual)
	}
	if actual := finalRouteOverrideAddressWithDomain(options.Route.Rules); actual != "" {
		t.Fatalf("expected no final override mode, got %q", actual)
	}
}

func TestRenderRouteOverrideAddressWithDomainUsesDirectModeForDirectFinal(t *testing.T) {
	defaultMode := boxOption.RouteOverrideAddressWithDomain(C.RouteOverrideAddressWithDomainAlways)
	directMode := boxOption.RouteOverrideAddressWithDomain(C.RouteOverrideAddressWithDomainDisable)
	template := &Template{Template: serenityOption.Template{
		DirectTag:                            "direct-out",
		DefaultTag:                           "direct-out",
		RouteOverrideAddressWithDomain:       defaultMode,
		RouteOverrideAddressWithDomainDirect: directMode,
	}}
	options := &boxOption.Options{}

	if err := template.renderRoute(M.Metadata{}, options); err != nil {
		t.Fatal(err)
	}
	if actual := finalRouteOverrideAddressWithDomain(options.Route.Rules); actual != directMode {
		t.Fatalf("expected direct final override mode %q, got %q", directMode, actual)
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

func routeRuleWithOverride(outbound string, mode string) boxOption.Rule {
	return boxOption.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: boxOption.DefaultRule{
			RuleAction: boxOption.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: boxOption.RouteActionOptions{
					Outbound: outbound,
					RawRouteOptionsActionOptions: boxOption.RawRouteOptionsActionOptions{
						OverrideAddressWithDomain: boxOption.RouteOverrideAddressWithDomain(mode),
					},
				},
			},
		},
	}
}

func finalRouteOverrideAddressWithDomain(rules []boxOption.Rule) boxOption.RouteOverrideAddressWithDomain {
	if len(rules) == 0 {
		return ""
	}
	action := rules[len(rules)-1].DefaultOptions.RuleAction
	if action.Action != C.RuleActionTypeRouteOptions {
		return ""
	}
	return action.RouteOptionsOptions.OverrideAddressWithDomain
}

func assertRouteOverrideAddressWithDomain(
	t *testing.T,
	rules []boxOption.Rule,
	directTag string,
	defaultMode boxOption.RouteOverrideAddressWithDomain,
	directMode boxOption.RouteOverrideAddressWithDomain,
) {
	t.Helper()
	for _, rule := range rules {
		if rule.Type == C.RuleTypeLogical {
			assertRouteOverrideAddressWithDomain(t, rule.LogicalOptions.Rules, directTag, defaultMode, directMode)
			assertRouteActionOverrideAddressWithDomain(t, rule.LogicalOptions.RuleAction, directTag, defaultMode, directMode)
		} else {
			assertRouteActionOverrideAddressWithDomain(t, rule.DefaultOptions.RuleAction, directTag, defaultMode, directMode)
		}
	}
}

func assertRouteActionOverrideAddressWithDomain(
	t *testing.T,
	action boxOption.RuleAction,
	directTag string,
	defaultMode boxOption.RouteOverrideAddressWithDomain,
	directMode boxOption.RouteOverrideAddressWithDomain,
) {
	t.Helper()
	if action.Action != C.RuleActionTypeRoute {
		return
	}
	expectedMode := defaultMode
	if action.RouteOptions.Outbound == directTag {
		expectedMode = directMode
	}
	if actual := action.RouteOptions.OverrideAddressWithDomain; actual != expectedMode {
		t.Fatalf("expected override mode %q for outbound %q, got %q", expectedMode, action.RouteOptions.Outbound, actual)
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
