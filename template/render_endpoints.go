package template

import (
	M "github.com/sagernet/serenity/common/metadata"
	"github.com/sagernet/serenity/subscription"
	"github.com/sagernet/sing-box/option"
)

func (t *Template) renderEndpoints(_ M.Metadata, options *option.Options, subscriptions []*subscription.Subscription) error {
	options.Endpoints = append(options.Endpoints, t.Endpoints...)
	for _, currentSubscription := range subscriptions {
		options.Endpoints = append(options.Endpoints, currentSubscription.Endpoints...)
	}
	return nil
}
