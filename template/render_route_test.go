package template

import (
	"context"
	"testing"

	M "github.com/sagernet/serenity/common/metadata"
	serenityOption "github.com/sagernet/serenity/option"
	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestRenderRouteStagedSniffOverride(t *testing.T) {
	template := &Template{
		Template: serenityOption.Template{
			SniffOverrideDestination: boxOption.SniffOverrideDestination(C.SniffOverrideDestinationIfResolvable),
		},
	}
	options := &boxOption.Options{}

	err := template.renderRoute(M.Metadata{}, options)
	if err != nil {
		t.Fatal(err)
	}
	initialSniffIndex := -1
	hijackDNSIndex := firstRouteActionIndex(options.Route.Rules, C.RuleActionTypeHijackDNS)
	resolveIndex := firstRouteActionIndex(options.Route.Rules, C.RuleActionTypeResolve)
	conditionalSniffIndex := -1
	for index, rule := range options.Route.Rules {
		if rule.DefaultOptions.Action == C.RuleActionTypeSniff &&
			string(rule.DefaultOptions.SniffOptions.OverrideDestination) == C.SniffOverrideDestinationSkip {
			initialSniffIndex = index
		}
		if rule.LogicalOptions.Action == C.RuleActionTypeSniff {
			conditionalSniffIndex = index
			if mode := string(rule.LogicalOptions.SniffOptions.OverrideDestination); mode != C.SniffOverrideDestinationIfResolvable {
				t.Fatalf("expected conditional sniff override mode %q, got %q", C.SniffOverrideDestinationIfResolvable, mode)
			}
			if rule.LogicalOptions.Mode != C.LogicalTypeAnd || len(rule.LogicalOptions.Rules) != 2 {
				t.Fatalf("expected two AND conditions for conditional sniff, got mode=%q rules=%d", rule.LogicalOptions.Mode, len(rule.LogicalOptions.Rules))
			}
			privateRule := rule.LogicalOptions.Rules[0].DefaultOptions
			geoIPRule := rule.LogicalOptions.Rules[1].DefaultOptions
			if !privateRule.IPIsPrivate || !privateRule.Invert {
				t.Fatal("expected inverted private IP condition")
			}
			if len(geoIPRule.RuleSet) != 1 || geoIPRule.RuleSet[0] != "geoip-cn" || !geoIPRule.Invert {
				t.Fatal("expected inverted geoip-cn condition")
			}
		}
	}
	indices := []int{initialSniffIndex, hijackDNSIndex, resolveIndex, conditionalSniffIndex}
	for index, ruleIndex := range indices {
		if ruleIndex == -1 {
			t.Fatalf("expected staged route rule %d, got indices %v", index, indices)
		}
	}
	for index := 1; index < len(indices); index++ {
		if indices[index-1] >= indices[index] {
			t.Fatalf("unexpected staged route order: skip=%d hijack=%d resolve=%d conditional=%d",
				initialSniffIndex, hijackDNSIndex, resolveIndex, conditionalSniffIndex)
		}
	}
}

func TestRenderRouteSniffOverrideModes(t *testing.T) {
	testCases := []struct {
		name                string
		overrideDestination boxOption.SniffOverrideDestination
		expectedModes       []string
	}{
		{
			name:          "default",
			expectedModes: []string{C.SniffOverrideDestinationSkip},
		},
		{
			name:                "disable",
			overrideDestination: boxOption.SniffOverrideDestination(C.SniffOverrideDestinationDisable),
			expectedModes:       []string{C.SniffOverrideDestinationSkip},
		},
		{
			name:                "always",
			overrideDestination: boxOption.SniffOverrideDestination(C.SniffOverrideDestinationAlways),
			expectedModes:       []string{C.SniffOverrideDestinationSkip, C.SniffOverrideDestinationAlways},
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			template := &Template{Template: serenityOption.Template{
				SniffOverrideDestination: testCase.overrideDestination,
			}}
			options := &boxOption.Options{}
			if err := template.renderRoute(M.Metadata{}, options); err != nil {
				t.Fatal(err)
			}
			var actualModes []string
			for _, rule := range options.Route.Rules {
				if rule.DefaultOptions.Action == C.RuleActionTypeSniff {
					actualModes = append(actualModes, string(rule.DefaultOptions.SniffOptions.OverrideDestination))
				}
				if rule.LogicalOptions.Action == C.RuleActionTypeSniff {
					actualModes = append(actualModes, string(rule.LogicalOptions.SniffOptions.OverrideDestination))
				}
			}
			if len(actualModes) != len(testCase.expectedModes) {
				t.Fatalf("expected sniff modes %v, got %v", testCase.expectedModes, actualModes)
			}
			for index := range actualModes {
				if actualModes[index] != testCase.expectedModes[index] {
					t.Fatalf("expected sniff modes %v, got %v", testCase.expectedModes, actualModes)
				}
			}
		})
	}
}

func TestRenderRouteSingleSniffOverrideCondition(t *testing.T) {
	template := &Template{Template: serenityOption.Template{
		DisableTrafficBypass:     true,
		SniffOverrideDestination: boxOption.SniffOverrideDestination(C.SniffOverrideDestinationAlways),
	}}
	options := &boxOption.Options{}
	if err := template.renderRoute(M.Metadata{}, options); err != nil {
		t.Fatal(err)
	}

	conditionalSniffCount := 0
	for _, rule := range options.Route.Rules {
		if rule.LogicalOptions.Action == C.RuleActionTypeSniff {
			t.Fatal("expected a default rule for a single sniff override condition")
		}
		if rule.DefaultOptions.Action != C.RuleActionTypeSniff ||
			string(rule.DefaultOptions.SniffOptions.OverrideDestination) != C.SniffOverrideDestinationAlways {
			continue
		}
		conditionalSniffCount++
		if !rule.DefaultOptions.IPIsPrivate || !rule.DefaultOptions.Invert {
			t.Fatal("expected an inverted private IP condition")
		}
	}
	if conditionalSniffCount != 1 {
		t.Fatalf("expected one conditional sniff rule, got %d", conditionalSniffCount)
	}
}

func TestTemplateSniffOverrideDestinationCompatibility(t *testing.T) {
	testCases := []struct {
		value    string
		expected string
	}{
		{`"skip"`, C.SniffOverrideDestinationSkip},
		{`"disable"`, C.SniffOverrideDestinationDisable},
		{`"always"`, C.SniffOverrideDestinationAlways},
		{`"if_resolvable"`, C.SniffOverrideDestinationIfResolvable},
		{`false`, C.SniffOverrideDestinationSkip},
		{`true`, C.SniffOverrideDestinationAlways},
	}
	for _, testCase := range testCases {
		var template serenityOption.Template
		err := json.UnmarshalContext(context.Background(), []byte(`{"sniff_override_destination":`+testCase.value+`}`), &template)
		if err != nil {
			t.Fatalf("unmarshal %s: %v", testCase.value, err)
		}
		if actual := string(template.SniffOverrideDestination); actual != testCase.expected {
			t.Fatalf("expected %q for %s, got %q", testCase.expected, testCase.value, actual)
		}
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

func hasRouteAction(rules []boxOption.Rule, action string) bool {
	for _, rule := range rules {
		if rule.DefaultOptions.Action == action || rule.LogicalOptions.Action == action {
			return true
		}
	}
	return false
}

func firstRouteActionIndex(rules []boxOption.Rule, action string) int {
	for index, rule := range rules {
		if rule.DefaultOptions.Action == action || rule.LogicalOptions.Action == action {
			return index
		}
	}
	return -1
}
