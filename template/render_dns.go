package template

import (
	"context"
	"net/netip"
	"net/url"

	M "github.com/sagernet/serenity/common/metadata"
	"github.com/sagernet/serenity/common/semver"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	BM "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
)

func parseDNSServerOptions(address string, detour string, addressResolver string) option.DNSServerOptions {
	serverURL, _ := url.Parse(address)
	var serverType string
	if serverURL != nil && serverURL.Scheme != "" {
		serverType = serverURL.Scheme
	} else {
		switch address {
		case "local":
			serverType = C.DNSTypeLocal
		default:
			serverType = C.DNSTypeUDP
		}
	}
	dialerOptions := option.DialerOptions{
		Detour: detour,
	}
	if addressResolver != "" {
		dialerOptions.DomainResolver = &option.DomainResolveOptions{
			Server: addressResolver,
		}
	}
	remoteOptions := option.RemoteDNSServerOptions{
		RawLocalDNSServerOptions: option.RawLocalDNSServerOptions{
			DialerOptions: dialerOptions,
		},
	}
	switch serverType {
	case C.DNSTypeLocal:
		return option.DNSServerOptions{
			Type: C.DNSTypeLocal,
			Options: &option.LocalDNSServerOptions{
				RawLocalDNSServerOptions: remoteOptions.RawLocalDNSServerOptions,
			},
		}
	case C.DNSTypeUDP:
		var serverAddr BM.Socksaddr
		if serverURL == nil || serverURL.Scheme == "" {
			serverAddr = BM.ParseSocksaddr(address)
		} else {
			serverAddr = BM.ParseSocksaddr(serverURL.Host)
		}
		remoteOptions.Server = serverAddr.AddrString()
		if serverAddr.Port != 0 && serverAddr.Port != 53 {
			remoteOptions.ServerPort = serverAddr.Port
		}
		return option.DNSServerOptions{
			Type:    C.DNSTypeUDP,
			Options: &remoteOptions,
		}
	case C.DNSTypeTCP:
		if serverURL != nil {
			serverAddr := BM.ParseSocksaddr(serverURL.Host)
			remoteOptions.Server = serverAddr.AddrString()
			if serverAddr.Port != 0 && serverAddr.Port != 53 {
				remoteOptions.ServerPort = serverAddr.Port
			}
		}
		return option.DNSServerOptions{
			Type:    C.DNSTypeTCP,
			Options: &remoteOptions,
		}
	case C.DNSTypeTLS, C.DNSTypeQUIC:
		if serverURL != nil {
			serverAddr := BM.ParseSocksaddr(serverURL.Host)
			remoteOptions.Server = serverAddr.AddrString()
			if serverAddr.Port != 0 && serverAddr.Port != 853 {
				remoteOptions.ServerPort = serverAddr.Port
			}
		}
		return option.DNSServerOptions{
			Type: serverType,
			Options: &option.RemoteTLSDNSServerOptions{
				RemoteDNSServerOptions: remoteOptions,
			},
		}
	case C.DNSTypeHTTPS, C.DNSTypeHTTP3:
		httpsOptions := option.RemoteHTTPSDNSServerOptions{
			RemoteTLSDNSServerOptions: option.RemoteTLSDNSServerOptions{
				RemoteDNSServerOptions: remoteOptions,
			},
		}
		if serverURL != nil {
			serverAddr := BM.ParseSocksaddr(serverURL.Host)
			httpsOptions.Server = serverAddr.AddrString()
			if serverAddr.Port != 0 && serverAddr.Port != 443 {
				httpsOptions.ServerPort = serverAddr.Port
			}
			if serverURL.Path != "/dns-query" {
				httpsOptions.Path = serverURL.Path
			}
		}
		return option.DNSServerOptions{
			Type:    serverType,
			Options: &httpsOptions,
		}
	default:
		return option.DNSServerOptions{
			Type:    C.DNSTypeUDP,
			Options: &remoteOptions,
		}
	}
}

func (t *Template) renderDNS(_ context.Context, metadata M.Metadata, options *option.Options) error {
	var domainStrategy option.DomainStrategy
	if t.DomainStrategy != option.DomainStrategy(C.DomainStrategyAsIS) {
		domainStrategy = t.DomainStrategy
	} else if t.EnableFakeIP {
		domainStrategy = option.DomainStrategy(C.DomainStrategyPreferIPv4)
	} else {
		domainStrategy = option.DomainStrategy(C.DomainStrategyIPv4Only)
	}
	dnsClientOptions := option.DNSClientOptions{
		Strategy: domainStrategy,
	}
	if t.EnableFakeIP && metadata.Version != nil && metadata.Version.LessThan(semver.ParseVersion("1.14.0-alpha.1")) {
		dnsClientOptions.IndependentCache = true
	}
	if t.EnableOptimisticDNSCache && (metadata.Version == nil || metadata.Version.GreaterThanOrEqual(semver.ParseVersion("1.14.0-alpha.1"))) {
		dnsClientOptions.Optimistic = &option.OptimisticDNSOptions{Enabled: true}
	}
	options.DNS = &option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{
			ReverseMapping:   !t.DisableTrafficBypass && metadata.Platform != M.PlatformUnknown && !metadata.Platform.IsApple(),
			DNSClientOptions: dnsClientOptions,
		},
	}
	dnsDefault := t.DNS
	if dnsDefault == "" {
		dnsDefault = DefaultDNS
	}
	dnsLocal := t.DNSLocal
	if dnsLocal == "" {
		dnsLocal = DefaultDNSLocal
	}
	directTag := t.DirectTag
	if directTag == "" {
		directTag = DefaultDirectTag
	}
	defaultTag := t.DefaultTag
	if defaultTag == "" {
		defaultTag = DefaultDefaultTag
	}

	var defaultAddressResolver string
	if dnsDefaultUrl, err := url.Parse(dnsDefault); err == nil && BM.IsDomainName(dnsDefaultUrl.Hostname()) {
		defaultAddressResolver = DNSLocalTag
	}

	defaultDNSOptions := parseDNSServerOptions(dnsDefault, defaultTag, defaultAddressResolver)
	defaultDNSOptions.Tag = DNSDefaultTag
	options.DNS.Servers = append(options.DNS.Servers, defaultDNSOptions)

	var localDNSIsDomain bool
	var localDNSOptions option.DNSServerOptions
	if t.DisableTrafficBypass {
		localDNSOptions = parseDNSServerOptions("local", "", "")
		localDNSOptions.Tag = DNSLocalTag
	} else {
		localDNSOptions = parseDNSServerOptions(dnsLocal, directTag, "")
		localDNSOptions.Tag = DNSLocalTag
		if BM.IsDomainName(dnsLocal) {
			localDNSIsDomain = true
		} else if dnsLocalUrl, err := url.Parse(dnsLocal); err == nil {
			switch dnsLocalUrl.Scheme {
			case "tcp", "udp", "tls", "https", "quic", "h3":
				localDNSIsDomain = true
			}
		}
		if localDNSIsDomain || t.EnableLocalSetup {
			if defaultAddressResolver == DNSLocalTag {
				setDNSServerDomainResolver(&defaultDNSOptions, DNSLocalSetupTag)
				options.DNS.Servers[len(options.DNS.Servers)-1] = defaultDNSOptions
			}
			setDNSServerDomainResolver(&localDNSOptions, DNSLocalSetupTag)
		}
	}
	options.DNS.Servers = append(options.DNS.Servers, localDNSOptions)
	if localDNSIsDomain || t.EnableLocalSetup {
		options.DNS.Servers = append(options.DNS.Servers, option.DNSServerOptions{
			Type:    C.DNSTypeLocal,
			Tag:     DNSLocalSetupTag,
			Options: &option.LocalDNSServerOptions{},
		})
	}
	if t.EnableFakeIP {
		var inet4Range, inet6Range *badoption.Prefix
		if t.CustomFakeIP != nil {
			inet4Range = t.CustomFakeIP.Inet4Range
			inet6Range = t.CustomFakeIP.Inet6Range
		}
		if inet4Range == nil {
			inet4Range = (*badoption.Prefix)(common.Ptr(netip.MustParsePrefix("198.18.0.0/15")))
		}
		if !t.DisableIPv6() && inet6Range == nil {
			inet6Range = (*badoption.Prefix)(common.Ptr(netip.MustParsePrefix("fc00::/18")))
		}
		options.DNS.Servers = append(options.DNS.Servers, option.DNSServerOptions{
			Tag:  DNSFakeIPTag,
			Type: C.DNSTypeFakeIP,
			Options: &option.FakeIPDNSServerOptions{
				Inet4Range: inet4Range,
				Inet6Range: inet6Range,
			},
		})
	}
	options.DNS.Servers = append(options.DNS.Servers, t.DNSServers...)

	options.DNS.Rules = append(options.DNS.Rules, t.prepareCustomDNSRules(t.StartDNSRules)...)

	clashModeRule := t.ClashModeRule
	if clashModeRule == "" {
		clashModeRule = "Rule"
	}
	clashModeGlobal := t.ClashModeGlobal
	if clashModeGlobal == "" {
		clashModeGlobal = "Global"
	}
	clashModeDirect := t.ClashModeDirect
	if clashModeDirect == "" {
		clashModeDirect = "Direct"
	}

	if !t.DisableClashMode {
		if t.EnableFakeIP {
			options.DNS.Rules = append(options.DNS.Rules, t.fakeIPDNSRule(func(rule *option.RawDefaultDNSRule) {
				rule.ClashMode = clashModeGlobal
			}))
		}
		options.DNS.Rules = append(options.DNS.Rules, option.DNSRule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultDNSRule{
				RawDefaultDNSRule: option.RawDefaultDNSRule{
					ClashMode: clashModeGlobal,
				},
				DNSRuleAction: option.DNSRuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.DNSRouteActionOptions{
						Server: DNSDefaultTag,
					},
				},
			},
		}, option.DNSRule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultDNSRule{
				RawDefaultDNSRule: option.RawDefaultDNSRule{
					ClashMode: clashModeDirect,
				},
				DNSRuleAction: option.DNSRuleAction{
					Action: C.RuleActionTypeRoute,
					RouteOptions: option.DNSRouteActionOptions{
						Server: DNSLocalTag,
					},
				},
			},
		})
	}
	options.DNS.Rules = append(options.DNS.Rules, t.prepareCustomDNSRules(t.PreDNSRules)...)
	if len(t.CustomDNSRules) == 0 {
		if !t.DisableTrafficBypass {
			options.DNS.Rules = append(options.DNS.Rules, option.DNSRule{
				Type: C.RuleTypeDefault,
				DefaultOptions: option.DefaultDNSRule{
					RawDefaultDNSRule: option.RawDefaultDNSRule{
						RuleSet: []string{"geosite-geolocation-cn"},
					},
					DNSRuleAction: option.DNSRuleAction{
						Action: C.RuleActionTypeRoute,
						RouteOptions: option.DNSRouteActionOptions{
							Server: DNSLocalTag,
						},
					},
				},
			})
			if !t.DisableDNSLeak {
				useEvaluate := metadata.Version == nil || metadata.Version.GreaterThanOrEqual(semver.ParseVersion("1.14.0-alpha.1"))
				if useEvaluate {
					if t.EnableFakeIP {
						options.DNS.Rules = append(options.DNS.Rules, t.fakeIPDNSRule(func(rule *option.RawDefaultDNSRule) {
							rule.ClashMode = clashModeRule
						}))
					}
					options.DNS.Rules = append(options.DNS.Rules, option.DNSRule{
						Type: C.RuleTypeDefault,
						DefaultOptions: option.DefaultDNSRule{
							RawDefaultDNSRule: option.RawDefaultDNSRule{
								ClashMode: clashModeRule,
							},
							DNSRuleAction: option.DNSRuleAction{
								Action: C.RuleActionTypeRoute,
								RouteOptions: option.DNSRouteActionOptions{
									Server: DNSDefaultTag,
								},
							},
						},
					})
					if t.EnableFakeIP {
						options.DNS.Rules = append(options.DNS.Rules, t.fakeIPDNSRule(func(rule *option.RawDefaultDNSRule) {
							rule.RuleSet = []string{"geosite-geolocation-!cn"}
						}))
					}
					options.DNS.Rules = append(options.DNS.Rules, option.DNSRule{
						Type: C.RuleTypeDefault,
						DefaultOptions: option.DefaultDNSRule{
							RawDefaultDNSRule: option.RawDefaultDNSRule{
								RuleSet: []string{"geosite-geolocation-!cn"},
							},
							DNSRuleAction: option.DNSRuleAction{
								Action: C.RuleActionTypeRoute,
								RouteOptions: option.DNSRouteActionOptions{
									Server: DNSDefaultTag,
								},
							},
						},
					}, option.DNSRule{
						Type: C.RuleTypeDefault,
						DefaultOptions: option.DefaultDNSRule{
							DNSRuleAction: option.DNSRuleAction{
								Action: C.RuleActionTypeEvaluate,
								RouteOptions: option.DNSRouteActionOptions{
									Server: DNSLocalTag,
								},
							},
						},
					}, option.DNSRule{
						Type: C.RuleTypeDefault,
						DefaultOptions: option.DefaultDNSRule{
							RawDefaultDNSRule: option.RawDefaultDNSRule{
								MatchResponse: &option.DNSRuleMatchResponse{Enabled: true},
								RuleSet:       []string{"geoip-cn"},
							},
							DNSRuleAction: option.DNSRuleAction{
								Action: C.RuleActionTypeRespond,
							},
						},
					}, t.fakeIPDNSRule(nil))
				} else {
					if t.EnableFakeIP {
						options.DNS.Rules = append(options.DNS.Rules, t.fakeIPDNSRule(func(rule *option.RawDefaultDNSRule) {
							rule.ClashMode = clashModeRule
						}))
					}
					options.DNS.Rules = append(options.DNS.Rules, option.DNSRule{
						Type: C.RuleTypeDefault,
						DefaultOptions: option.DefaultDNSRule{
							RawDefaultDNSRule: option.RawDefaultDNSRule{
								ClashMode: clashModeRule,
							},
							DNSRuleAction: option.DNSRuleAction{
								Action: C.RuleActionTypeRoute,
								RouteOptions: option.DNSRouteActionOptions{
									Server: DNSDefaultTag,
								},
							},
						},
					}, option.DNSRule{
						Type: C.RuleTypeLogical,
						LogicalOptions: option.LogicalDNSRule{
							RawLogicalDNSRule: option.RawLogicalDNSRule{
								Mode: C.LogicalTypeAnd,
								Rules: []option.DNSRule{
									{
										Type: C.RuleTypeDefault,
										DefaultOptions: option.DefaultDNSRule{
											RawDefaultDNSRule: option.RawDefaultDNSRule{
												RuleSet: []string{"geoip-cn"},
											},
										},
									},
									{
										Type: C.RuleTypeDefault,
										DefaultOptions: option.DefaultDNSRule{
											RawDefaultDNSRule: option.RawDefaultDNSRule{
												RuleSet: []string{"geosite-geolocation-!cn"},
												Invert:  true,
											},
										},
									},
								},
							},
							DNSRuleAction: option.DNSRuleAction{
								Action: C.RuleActionTypeRoute,
								RouteOptions: option.DNSRouteActionOptions{
									Server: DNSLocalTag,
								},
							},
						},
					})
				}
			}
		}
	} else {
		options.DNS.Rules = append(options.DNS.Rules, t.prepareCustomDNSRules(t.CustomDNSRules)...)
	}
	return nil
}

func (t *Template) prepareCustomDNSRules(rules []option.DNSRule) []option.DNSRule {
	if !t.InheritFakeIPRewriteTTL || t.FakeIPRewriteTTL == nil {
		return rules
	}
	preparedRules := make([]option.DNSRule, len(rules))
	copy(preparedRules, rules)
	for index := range preparedRules {
		rule := &preparedRules[index]
		if rule.Type != C.RuleTypeDefault || rule.DefaultOptions.RouteOptions.Server != DNSFakeIPTag || rule.DefaultOptions.RouteOptions.RewriteTTL != nil {
			continue
		}
		rule.DefaultOptions.RouteOptions.RewriteTTL = t.FakeIPRewriteTTL
	}
	return preparedRules
}

func (t *Template) fakeIPDNSRule(configure func(rule *option.RawDefaultDNSRule)) option.DNSRule {
	rawRule := option.RawDefaultDNSRule{
		QueryType: []option.DNSQueryType{
			option.DNSQueryType(mDNS.TypeA),
			option.DNSQueryType(mDNS.TypeAAAA),
		},
	}
	if configure != nil {
		configure(&rawRule)
	}
	return option.DNSRule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultDNSRule{
			RawDefaultDNSRule: rawRule,
			DNSRuleAction: option.DNSRuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.DNSRouteActionOptions{
					Server:     DNSFakeIPTag,
					RewriteTTL: t.FakeIPRewriteTTL,
				},
			},
		},
	}
}

func setDNSServerDomainResolver(server *option.DNSServerOptions, resolver string) {
	switch opts := server.Options.(type) {
	case *option.LocalDNSServerOptions:
		opts.DialerOptions.DomainResolver = &option.DomainResolveOptions{Server: resolver}
	case *option.RemoteDNSServerOptions:
		opts.DialerOptions.DomainResolver = &option.DomainResolveOptions{Server: resolver}
	case *option.RemoteTLSDNSServerOptions:
		opts.DialerOptions.DomainResolver = &option.DomainResolveOptions{Server: resolver}
	case *option.RemoteHTTPSDNSServerOptions:
		opts.DialerOptions.DomainResolver = &option.DomainResolveOptions{Server: resolver}
	}
}
