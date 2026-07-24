package parser

import (
	"context"

	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type Result struct {
	Outbounds []option.Outbound
	Endpoints []option.Endpoint
}

type subscriptionParser func(ctx context.Context, content string) (Result, error)

func outboundParser(parser func(context.Context, string) ([]option.Outbound, error)) subscriptionParser {
	return func(ctx context.Context, content string) (Result, error) {
		outbounds, err := parser(ctx, content)
		return Result{Outbounds: outbounds}, err
	}
}

var subscriptionParsers = []subscriptionParser{
	outboundParser(ParseBoxSubscription),
	ParseClashSubscription,
	outboundParser(ParseSIP008Subscription),
	outboundParser(ParseRawSubscription),
}

func ParseSubscription(ctx context.Context, content string) (Result, error) {
	var pErr error
	for _, parser := range subscriptionParsers {
		result, err := parser(ctx, content)
		if len(result.Outbounds)+len(result.Endpoints) > 0 {
			return result, err
		}
		pErr = E.Errors(pErr, err)
	}
	return Result{}, E.Cause(pErr, "no servers or endpoints found")
}
