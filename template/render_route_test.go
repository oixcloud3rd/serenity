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

func TestRenderRouteSniffOverrideDestination(t *testing.T) {
	template := &Template{
		Template: serenityOption.Template{
			SniffOverrideDestination: boxOption.SniffOverrideDestination(C.SniffOverrideDestinationDNSEvaluate),
		},
	}
	options := &boxOption.Options{}

	err := template.renderRoute(M.Metadata{}, options)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range options.Route.Rules {
		if rule.DefaultOptions.Action != C.RuleActionTypeSniff {
			continue
		}
		if actual := string(rule.DefaultOptions.SniffOptions.OverrideDestination); actual != C.SniffOverrideDestinationDNSEvaluate {
			t.Fatalf("expected sniff override destination %q, got %q", C.SniffOverrideDestinationDNSEvaluate, actual)
		}
		return
	}
	t.Fatal("expected sniff route rule")
}

func TestTemplateSniffOverrideDestinationCompatibility(t *testing.T) {
	testCases := []struct {
		value    string
		expected string
	}{
		{`"disabled"`, C.SniffOverrideDestinationDisabled},
		{`"always"`, C.SniffOverrideDestinationAlways},
		{`"dns_evaluate"`, C.SniffOverrideDestinationDNSEvaluate},
		{`false`, C.SniffOverrideDestinationDisabled},
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
