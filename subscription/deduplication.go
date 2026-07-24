package subscription

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"sync"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/task"
)

func Deduplication(ctx context.Context, servers []option.Outbound) []option.Outbound {
	resolveCtx := &resolveContext{
		ctx:      ctx,
		resolver: net.DefaultResolver,
	}

	uniqueServers := make([]netip.AddrPort, len(servers))
	var (
		resolveGroup task.Group
		resultAccess sync.Mutex
	)
	for index, server := range servers {
		currentIndex := index
		currentServer := server
		resolveGroup.Append0(func(ctx context.Context) error {
			destination := resolveDestination(resolveCtx, currentServer)
			if destination.IsValid() {
				resultAccess.Lock()
				uniqueServers[currentIndex] = destination
				resultAccess.Unlock()
			}
			return nil
		})
	}
	resolveGroup.Concurrency(5)
	_ = resolveGroup.Run(ctx)
	uniqueServerMap := make(map[netip.AddrPort]bool)
	var newServers []option.Outbound
	for index, server := range servers {
		destination := uniqueServers[index]
		if destination.IsValid() {
			if uniqueServerMap[destination] {
				continue
			}
			uniqueServerMap[destination] = true
		}
		newServers = append(newServers, server)
	}
	return newServers
}

func DeduplicateEndpoints(endpoints []option.Endpoint) []option.Endpoint {
	var result []option.Endpoint
	seenDestinations := make(map[string]bool)
	for _, endpoint := range endpoints {
		destination := endpointDestination(endpoint)
		if destination != "" {
			key := endpoint.Type + "\x00" + destination
			if seenDestinations[key] {
				continue
			}
			seenDestinations[key] = true
		} else {
			duplicate := false
			for _, existing := range result {
				if existing.Type == endpoint.Type && reflect.DeepEqual(existing.Options, endpoint.Options) {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
		}
		result = append(result, endpoint)
	}
	return result
}

func endpointDestination(endpoint option.Endpoint) string {
	switch endpointOptions := endpoint.Options.(type) {
	case *option.WireGuardEndpointOptions:
		if len(endpointOptions.Peers) > 0 {
			peer := endpointOptions.Peers[0]
			return net.JoinHostPort(peer.Address, strconv.Itoa(int(peer.Port)))
		}
	case *option.OpenVPNClientEndpointOptions:
		if endpointOptions.Server != "" {
			return net.JoinHostPort(endpointOptions.Server, strconv.Itoa(int(endpointOptions.ServerPort)))
		}
		if len(endpointOptions.Servers) > 0 {
			server := endpointOptions.Servers[0]
			return net.JoinHostPort(server.Server, strconv.Itoa(int(server.ServerPort)))
		}
	case *option.TailscaleEndpointOptions:
		if endpointOptions.ControlURL != "" || endpointOptions.ExitNode != "" {
			return endpointOptions.ControlURL + "\x00" + endpointOptions.ExitNode
		}
	}
	return ""
}

type resolveContext struct {
	ctx      context.Context
	resolver *net.Resolver
}

func resolveDestination(ctx *resolveContext, server option.Outbound) netip.AddrPort {
	serverOptionsWrapper, loaded := server.Options.(option.ServerOptionsWrapper)
	if !loaded {
		return netip.AddrPort{}
	}
	serverOptions := serverOptionsWrapper.TakeServerOptions().Build()
	if serverOptions.IsIP() {
		return serverOptions.AddrPort()
	}
	if M.IsDomainName(serverOptions.Fqdn) {
		addresses, lookupErr := ctx.resolver.LookupNetIP(ctx.ctx, "ip", serverOptions.Fqdn)
		if lookupErr == nil && len(addresses) > 0 {
			address := addresses[0]
			for _, candidate := range addresses {
				if candidate.Is4() {
					address = candidate
					break
				}
			}
			return netip.AddrPortFrom(address, serverOptions.Port)
		}
	}
	return netip.AddrPort{}
}
