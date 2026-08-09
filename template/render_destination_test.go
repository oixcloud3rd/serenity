package template

import (
	"context"
	"testing"

	"github.com/sagernet/serenity/common/metadata"
	"github.com/sagernet/serenity/common/semver"
	serenityOption "github.com/sagernet/serenity/option"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json"
)

func TestRenderDestinationStrategiesByLeafCategory(t *testing.T) {
	template := &Template{Template: serenityOption.Template{
		DirectTag: "direct-out",
		DestinationStrategy: &serenityOption.DestinationStrategy{
			Strategy:           C.DestinationStrategyPreferDestination,
			OverrideWithDomain: &serenityOption.OverrideWithDomainOptions{IPOnly: true},
		},
		DestinationStrategyDirect: &serenityOption.DestinationStrategy{
			Strategy: C.DestinationStrategyPreferDestination,
		},
		DestinationStrategyEndpoint: &serenityOption.DestinationStrategy{
			Strategy: C.DestinationStrategyPreferDestinationAddresses,
		},
	}}
	options := &boxOption.Options{
		Outbounds: []boxOption.Outbound{
			{Type: C.TypeDirect, Tag: "direct-out", Options: &boxOption.DirectOutboundOptions{}},
			{Type: C.TypeVMess, Tag: "proxy", Options: &boxOption.VMessOutboundOptions{}},
			{Type: C.TypeSelector, Tag: "group", Options: &boxOption.SelectorOutboundOptions{}},
		},
		Endpoints: []boxOption.Endpoint{
			{Type: C.TypeTailscale, Tag: "endpoint", Options: &boxOption.TailscaleEndpointOptions{}},
		},
	}

	template.renderDestinationStrategies(metadata.Metadata{}, options)

	direct := destinationStrategyOf(t, options.Outbounds[0].Options)
	if direct.Strategy != C.DestinationStrategyPreferDestination || direct.OverrideWithDomain != nil {
		t.Fatalf("unexpected direct strategy: %#v", direct)
	}
	proxy := destinationStrategyOf(t, options.Outbounds[1].Options)
	if proxy.Strategy != C.DestinationStrategyPreferDestination || proxy.OverrideWithDomain == nil || proxy.OverrideWithDomain.Evaluator != DefaultDomainEvaluatorTag || !proxy.OverrideWithDomain.IPOnly {
		t.Fatalf("unexpected proxy strategy: %#v", proxy)
	}
	if _, loaded := options.Outbounds[2].Options.(boxOption.DestinationStrategyOptionsWrapper); loaded {
		t.Fatal("selector must not support destination strategy")
	}
	endpoint := destinationStrategyOf(t, options.Endpoints[0].Options)
	if endpoint.Strategy != C.DestinationStrategyPreferDestinationAddresses || endpoint.OverrideWithDomain != nil {
		t.Fatalf("unexpected endpoint strategy: %#v", endpoint)
	}
	if len(options.DomainEvaluators) != 1 || options.DomainEvaluators[0].Tag != DefaultDomainEvaluatorTag || options.DomainEvaluators[0].Server != "" {
		t.Fatalf("unexpected domain evaluators: %#v", options.DomainEvaluators)
	}
	ctx := include.Context(context.Background())
	content, err := json.MarshalContext(ctx, options)
	if err != nil {
		t.Fatal(err)
	}
	var parsed boxOption.Options
	if err = json.UnmarshalContext(ctx, content, &parsed); err != nil {
		t.Fatalf("generated options failed sing-box validation: %v", err)
	}
}

func TestRenderDestinationStrategiesWithoutEvaluation(t *testing.T) {
	template := &Template{Template: serenityOption.Template{
		DestinationStrategy: &serenityOption.DestinationStrategy{Strategy: C.DestinationStrategyPreferDestination},
	}}
	options := &boxOption.Options{Outbounds: []boxOption.Outbound{
		{Type: C.TypeVMess, Tag: "proxy", Options: &boxOption.VMessOutboundOptions{}},
	}}

	template.renderDestinationStrategies(metadata.Metadata{}, options)

	if len(options.DomainEvaluators) != 0 {
		t.Fatalf("expected no evaluator, got %#v", options.DomainEvaluators)
	}
}

func TestRenderDestinationStrategiesNormalizesExistingEvaluation(t *testing.T) {
	existing := &boxOption.DestinationStrategy{
		Strategy: C.DestinationStrategyPreferDestination,
		OverrideWithDomain: &boxOption.OverrideWithDomainOptions{
			Evaluator: "custom",
		},
	}
	options := &boxOption.Options{Outbounds: []boxOption.Outbound{
		{Type: C.TypeVMess, Tag: "proxy", Options: &boxOption.VMessOutboundOptions{
			DestinationStrategyOptions: boxOption.DestinationStrategyOptions{DestinationStrategy: existing},
		}},
	}}

	new(Template).renderDestinationStrategies(metadata.Metadata{}, options)

	outputStrategy := destinationStrategyOf(t, options.Outbounds[0].Options)
	if outputStrategy.OverrideWithDomain.Evaluator != DefaultDomainEvaluatorTag {
		t.Fatalf("expected default evaluator reference, got %q", outputStrategy.OverrideWithDomain.Evaluator)
	}
	if existing.OverrideWithDomain.Evaluator != "custom" {
		t.Fatalf("expected source strategy to remain unchanged, got %q", existing.OverrideWithDomain.Evaluator)
	}
	if len(options.DomainEvaluators) != 1 || options.DomainEvaluators[0].Tag != DefaultDomainEvaluatorTag {
		t.Fatalf("unexpected domain evaluators: %#v", options.DomainEvaluators)
	}
}

func TestRenderDestinationStrategiesVersionBoundary(t *testing.T) {
	template := &Template{Template: serenityOption.Template{
		DestinationStrategy: &serenityOption.DestinationStrategy{
			Strategy:           C.DestinationStrategyPreferDestination,
			OverrideWithDomain: &serenityOption.OverrideWithDomainOptions{},
		},
	}}
	for _, testCase := range []struct {
		name    string
		version string
		apply   bool
	}{
		{name: "before beta 12", version: "1.14.0-beta.11"},
		{name: "beta 12", version: "1.14.0-beta.12", apply: true},
		{name: "stable", version: "1.14.0", apply: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			existing := &boxOption.DestinationStrategy{Strategy: C.DestinationStrategyPreferDestination}
			options := &boxOption.Options{Outbounds: []boxOption.Outbound{
				{Type: C.TypeVMess, Tag: "proxy", Options: &boxOption.VMessOutboundOptions{
					DestinationStrategyOptions: boxOption.DestinationStrategyOptions{DestinationStrategy: existing},
				}},
			}}
			template.renderDestinationStrategies(metadata.Metadata{
				Version: common.Ptr(semver.ParseVersion(testCase.version)),
			}, options)
			strategy := options.Outbounds[0].Options.(*boxOption.VMessOutboundOptions).DestinationStrategy
			if testCase.apply {
				if strategy == nil || strategy.OverrideWithDomain == nil {
					t.Fatalf("expected destination strategy at %s", testCase.version)
				}
			} else {
				if strategy != nil {
					t.Fatalf("expected destination strategy to be removed at %s: %#v", testCase.version, strategy)
				}
				if len(options.DomainEvaluators) != 0 {
					t.Fatalf("expected no evaluator at %s", testCase.version)
				}
				if existing.Strategy != C.DestinationStrategyPreferDestination {
					t.Fatal("expected source strategy to remain unchanged")
				}
			}
		})
	}
}

func destinationStrategyOf(t *testing.T, options any) *boxOption.DestinationStrategy {
	t.Helper()
	wrapper, loaded := options.(boxOption.DestinationStrategyOptionsWrapper)
	if !loaded || wrapper.TakeDestinationStrategy() == nil {
		t.Fatalf("missing destination strategy in %T", options)
	}
	return wrapper.TakeDestinationStrategy()
}
