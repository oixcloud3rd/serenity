package template

import (
	"fmt"
	"net"
	"strings"

	C "github.com/sagernet/serenity/constant"
	"github.com/sagernet/serenity/subscription"
	boxOption "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func normalizeDeduplicationStrategy(strategy string) (string, error) {
	if strategy == "" {
		return C.DeduplicationRename, nil
	}
	switch strategy {
	case C.DeduplicationRename,
		C.DeduplicationFirst,
		C.DeduplicationLast,
		C.DeduplicationPreferIPv4,
		C.DeduplicationPreferIPv6,
		C.DeduplicationPreferDomainThenIPv4,
		C.DeduplicationPreferDomainThenIPv6:
		return strategy, nil
	default:
		return "", E.New("deduplication_strategy must be one of: rename, first, last, prefer_ipv4, prefer_ipv6, prefer_domain_then_ipv4, prefer_domain_then_ipv6")
	}
}

type proxyRef struct {
	subIndex int
	outbound *boxOption.Outbound
	endpoint *boxOption.Endpoint
}

func (r proxyRef) tag() string {
	if r.outbound != nil {
		return r.outbound.Tag
	}
	return r.endpoint.Tag
}

func (r *proxyRef) setTag(tag string) {
	if r.outbound != nil {
		r.outbound.Tag = tag
	} else {
		r.endpoint.Tag = tag
	}
}

func (r proxyRef) server() string {
	if r.outbound != nil {
		return getOutboundServer(*r.outbound)
	}
	return getEndpointServer(*r.endpoint)
}

func deduplicateTemplateSubscriptions(subscriptions []*subscription.Subscription, strategy string) ([]*subscription.Subscription, error) {
	normalized, err := normalizeDeduplicationStrategy(strategy)
	if err != nil {
		return nil, err
	}
	if len(subscriptions) == 0 {
		return subscriptions, nil
	}

	refs := make([]proxyRef, 0)
	for subIndex, sub := range subscriptions {
		for _, outbound := range sub.Servers {
			outboundCopy := outbound
			refs = append(refs, proxyRef{
				subIndex: subIndex,
				outbound: &outboundCopy,
			})
		}
		for _, endpoint := range sub.Endpoints {
			endpointCopy := endpoint
			refs = append(refs, proxyRef{
				subIndex: subIndex,
				endpoint: &endpointCopy,
			})
		}
	}

	if normalized == C.DeduplicationRename {
		seen := make(map[string]int)
		for i := range refs {
			tag := refs[i].tag()
			if count, exists := seen[tag]; exists {
				count++
				seen[tag] = count
				refs[i].setTag(fmt.Sprintf("%s (%d)", tag, count))
			} else {
				seen[tag] = 0
			}
		}
	} else {
		seen := make(map[string][]int)
		for i, ref := range refs {
			seen[ref.tag()] = append(seen[ref.tag()], i)
		}

		keep := make(map[int]bool)
		for _, indices := range seen {
			if len(indices) == 1 {
				keep[indices[0]] = true
				continue
			}

			var selectedIndex int
			switch normalized {
			case C.DeduplicationFirst:
				selectedIndex = indices[0]
			case C.DeduplicationLast:
				selectedIndex = indices[len(indices)-1]
			default:
				selectedIndex = indices[0]
				bestPriority := -1

				for _, idx := range indices {
					server := refs[idx].server()
					addressType := getAddressType(server)
					priority := getAddressPriority(addressType, normalized)
					if priority > bestPriority {
						bestPriority = priority
						selectedIndex = idx
					}
				}
			}

			keep[selectedIndex] = true
		}

		filtered := refs[:0]
		for i, ref := range refs {
			if keep[i] {
				filtered = append(filtered, ref)
			}
		}
		refs = filtered
	}

	perSubscription := make([][]boxOption.Outbound, len(subscriptions))
	perSubscriptionEndpoints := make([][]boxOption.Endpoint, len(subscriptions))
	for _, ref := range refs {
		if ref.outbound != nil {
			perSubscription[ref.subIndex] = append(perSubscription[ref.subIndex], *ref.outbound)
		} else {
			perSubscriptionEndpoints[ref.subIndex] = append(perSubscriptionEndpoints[ref.subIndex], *ref.endpoint)
		}
	}

	deduped := make([]*subscription.Subscription, len(subscriptions))
	for i, sub := range subscriptions {
		copied := *sub
		copied.Servers = perSubscription[i]
		copied.Endpoints = perSubscriptionEndpoints[i]
		deduped[i] = &copied
	}

	return deduped, nil
}

func getEndpointServer(endpoint boxOption.Endpoint) string {
	switch opts := endpoint.Options.(type) {
	case *boxOption.WireGuardEndpointOptions:
		if len(opts.Peers) > 0 {
			return opts.Peers[0].Address
		}
	case *boxOption.OpenVPNClientEndpointOptions:
		if opts.Server != "" {
			return opts.Server
		}
		if len(opts.Servers) > 0 {
			return opts.Servers[0].Server
		}
	}
	return ""
}

func getOutboundServer(outbound boxOption.Outbound) string {
	switch opts := outbound.Options.(type) {
	case *boxOption.ShadowsocksOutboundOptions:
		return opts.Server
	case *boxOption.ShadowsocksROutboundOptions:
		return opts.Server
	case *boxOption.VMessOutboundOptions:
		return opts.Server
	case *boxOption.VLESSOutboundOptions:
		return opts.Server
	case *boxOption.TrojanOutboundOptions:
		return opts.Server
	case *boxOption.Hysteria2OutboundOptions:
		return opts.Server
	case *boxOption.HysteriaOutboundOptions:
		return opts.Server
	case *boxOption.AnyTLSOutboundOptions:
		return opts.Server
	case *boxOption.SnellOutboundOptions:
		return opts.Server
	case *boxOption.SSHOutboundOptions:
		return opts.Server
	case *boxOption.TUICOutboundOptions:
		return opts.Server
	case *boxOption.SOCKSOutboundOptions:
		return opts.Server
	case *boxOption.HTTPOutboundOptions:
		return opts.Server
	default:
		return ""
	}
}

func getAddressType(address string) string {
	if address == "" {
		return ""
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return C.AddressTypeDomain
	}
	if strings.Contains(ip.String(), ":") {
		return C.AddressTypeIPv6
	}
	return C.AddressTypeIPv4
}

func getAddressPriority(addressType string, strategy string) int {
	switch strategy {
	case C.DeduplicationPreferIPv4:
		switch addressType {
		case C.AddressTypeIPv4:
			return 3
		case C.AddressTypeDomain:
			return 2
		case C.AddressTypeIPv6:
			return 1
		}
	case C.DeduplicationPreferIPv6:
		switch addressType {
		case C.AddressTypeIPv6:
			return 3
		case C.AddressTypeDomain:
			return 2
		case C.AddressTypeIPv4:
			return 1
		}
	case C.DeduplicationPreferDomainThenIPv4:
		switch addressType {
		case C.AddressTypeDomain:
			return 3
		case C.AddressTypeIPv4:
			return 2
		case C.AddressTypeIPv6:
			return 1
		}
	case C.DeduplicationPreferDomainThenIPv6:
		switch addressType {
		case C.AddressTypeDomain:
			return 3
		case C.AddressTypeIPv6:
			return 2
		case C.AddressTypeIPv4:
			return 1
		}
	}
	return 0
}
