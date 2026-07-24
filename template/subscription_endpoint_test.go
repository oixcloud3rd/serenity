package template

import (
	"testing"

	M "github.com/sagernet/serenity/common/metadata"
	serenityOption "github.com/sagernet/serenity/option"
	"github.com/sagernet/serenity/subscription"
	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
)

func TestSubscriptionEndpointsMergeAndJoinGroups(t *testing.T) {
	currentSubscription := &subscription.Subscription{
		Subscription: serenityOption.Subscription{Name: "managed", GenerateSelector: true, GenerateURLTest: true},
		Endpoints:    []boxOption.Endpoint{{Type: C.TypeTailscale, Tag: "tailnet", Options: &boxOption.TailscaleEndpointOptions{}}},
	}
	template := &Template{Template: serenityOption.Template{
		Endpoints: []boxOption.Endpoint{{Type: C.TypeTailscale, Tag: "template-endpoint", Options: &boxOption.TailscaleEndpointOptions{}}},
	}}
	options := &boxOption.Options{
		Route:     &boxOption.RouteOptions{},
		Endpoints: []boxOption.Endpoint{{Type: C.TypeTailscale, Tag: "profile-endpoint", Options: &boxOption.TailscaleEndpointOptions{}}},
	}
	if err := template.renderEndpoints(M.Metadata{}, options, []*subscription.Subscription{currentSubscription}); err != nil {
		t.Fatal(err)
	}
	if len(options.Endpoints) != 3 {
		t.Fatalf("expected profile, template, and subscription endpoints, got %#v", options.Endpoints)
	}
	if err := template.renderOutbounds(M.Metadata{}, options, nil, []*subscription.Subscription{currentSubscription}); err != nil {
		t.Fatal(err)
	}
	for _, groupTag := range []string{"managed", "managed - URLTest"} {
		group := findTestOutbound(options.Outbounds, groupTag)
		if group == nil {
			t.Fatalf("missing generated group %q", groupTag)
		}
		var tags []string
		switch groupOptions := group.Options.(type) {
		case *boxOption.SelectorOutboundOptions:
			tags = groupOptions.Outbounds
		case *boxOption.URLTestOutboundOptions:
			tags = groupOptions.Outbounds
		}
		if len(tags) != 1 || tags[0] != "tailnet" {
			t.Fatalf("endpoint tag missing from %q: %#v", groupTag, tags)
		}
	}
}

func TestDeduplicationStrategyCoversOutboundEndpointCollisions(t *testing.T) {
	subscriptions := []*subscription.Subscription{{
		Subscription: serenityOption.Subscription{Name: "managed"},
		Servers:      []boxOption.Outbound{{Type: C.TypeDirect, Tag: "duplicate", Options: &boxOption.DirectOutboundOptions{}}},
		Endpoints:    []boxOption.Endpoint{{Type: C.TypeTailscale, Tag: "duplicate", Options: &boxOption.TailscaleEndpointOptions{}}},
	}}
	deduped, err := deduplicateTemplateSubscriptions(subscriptions, "rename")
	if err != nil {
		t.Fatal(err)
	}
	if deduped[0].Servers[0].Tag != "duplicate" || deduped[0].Endpoints[0].Tag != "duplicate (1)" {
		t.Fatalf("cross-kind duplicate tags were not renamed: %#v %#v", deduped[0].Servers, deduped[0].Endpoints)
	}
	if subscriptions[0].Endpoints[0].Tag != "duplicate" {
		t.Fatal("deduplication mutated the source subscription")
	}
}

func findTestOutbound(outbounds []boxOption.Outbound, tag string) *boxOption.Outbound {
	for index := range outbounds {
		if outbounds[index].Tag == tag {
			return &outbounds[index]
		}
	}
	return nil
}
