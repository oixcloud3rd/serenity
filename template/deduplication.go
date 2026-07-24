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

type outboundRef struct {
	subIndex int
	outbound boxOption.Outbound
}

func deduplicateTemplateSubscriptions(subscriptions []*subscription.Subscription, strategy string) ([]*subscription.Subscription, error) {
	normalized, err := normalizeDeduplicationStrategy(strategy)
	if err != nil {
		return nil, err
	}
	if len(subscriptions) == 0 {
		return subscriptions, nil
	}

	refs := make([]outboundRef, 0)
	for subIndex, sub := range subscriptions {
		for _, outbound := range sub.Servers {
			refs = append(refs, outboundRef{
				subIndex: subIndex,
				outbound: outbound,
			})
		}
	}

	if normalized == C.DeduplicationRename {
		seen := make(map[string]int)
		for i := range refs {
			tag := refs[i].outbound.Tag
			if count, exists := seen[tag]; exists {
				count++
				seen[tag] = count
				refs[i].outbound.Tag = fmt.Sprintf("%s (%d)", tag, count)
			} else {
				seen[tag] = 0
			}
		}
	} else {
		seen := make(map[string][]int)
		for i, ref := range refs {
			seen[ref.outbound.Tag] = append(seen[ref.outbound.Tag], i)
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
					server := getOutboundServer(refs[idx].outbound)
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
	for _, ref := range refs {
		perSubscription[ref.subIndex] = append(perSubscription[ref.subIndex], ref.outbound)
	}

	deduped := make([]*subscription.Subscription, len(subscriptions))
	for i, sub := range subscriptions {
		copied := *sub
		copied.Servers = perSubscription[i]
		deduped[i] = &copied
	}

	return deduped, nil
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
