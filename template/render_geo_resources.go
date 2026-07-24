package template

import (
	M "github.com/sagernet/serenity/common/metadata"
	"github.com/sagernet/serenity/common/semver"
	"github.com/sagernet/serenity/constant"
	"github.com/sagernet/serenity/option"
	C "github.com/sagernet/sing-box/constant"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
)

func (t *Template) renderGeoResources(metadata M.Metadata, options *boxOption.Options) {
	useHTTPClients := supportsHTTPClients(metadata)
	if len(t.CustomRuleSet) == 0 {
		var (
			downloadURL    string
			downloadDetour string
			branchSplit    string
		)
		if t.EnableJSDelivr {
			downloadURL = "https://testingcf.jsdelivr.net/gh/"
			if t.DirectTag != "" {
				downloadDetour = t.DirectTag
			} else {
				downloadDetour = DefaultDirectTag
			}
			branchSplit = "@"
		} else {
			downloadURL = "https://raw.githubusercontent.com/"
			branchSplit = "/"
		}
		options.Route.RuleSet = []boxOption.RuleSet{
			{
				Type:   C.RuleSetTypeRemote,
				Tag:    "geoip-cn",
				Format: C.RuleSetFormatBinary,
				RemoteOptions: boxOption.RemoteRuleSet{
					URL: downloadURL + "SagerNet/sing-geoip" + branchSplit + "rule-set/geoip-cn.srs",
				},
			},
			{
				Type:   C.RuleSetTypeRemote,
				Tag:    "geosite-geolocation-cn",
				Format: C.RuleSetFormatBinary,
				RemoteOptions: boxOption.RemoteRuleSet{
					URL: downloadURL + "SagerNet/sing-geosite" + branchSplit + "rule-set/geosite-geolocation-cn.srs",
				},
			},
			{
				Type:   C.RuleSetTypeRemote,
				Tag:    "geosite-geolocation-!cn",
				Format: C.RuleSetFormatBinary,
				RemoteOptions: boxOption.RemoteRuleSet{
					URL: downloadURL + "SagerNet/sing-geosite" + branchSplit + "rule-set/geosite-geolocation-!cn.srs",
				},
			},
		}
		applyRemoteRuleSetHTTPClient(options.Route.RuleSet, useHTTPClients, downloadDetour)
	}
	options.Route.RuleSet = append(options.Route.RuleSet, t.renderRuleSet(metadata, t.PostRuleSet)...)
	if useHTTPClients {
		t.renderHTTPClients(options)
	}
}

func (t *Template) renderHTTPClients(options *boxOption.Options) {
	if len(t.HTTPClients) > 0 {
		options.HTTPClients = append(options.HTTPClients, t.HTTPClients...)
		options.Route.DefaultHTTPClient = t.DefaultHTTPClient
		return
	}
	if t.DefaultHTTPClient != "" {
		options.Route.DefaultHTTPClient = t.DefaultHTTPClient
		return
	}
	if !hasRemoteRuleSet(options.Route.RuleSet) {
		return
	}
	defaultTag := t.DefaultTag
	if defaultTag == "" {
		defaultTag = DefaultDefaultTag
	}
	options.HTTPClients = append(options.HTTPClients, boxOption.HTTPClient{
		Tag: DefaultHTTPClientTag,
		DialerOptions: boxOption.DialerOptions{
			Detour: defaultTag,
		},
	})
	options.Route.DefaultHTTPClient = DefaultHTTPClientTag
}

func hasRemoteRuleSet(ruleSets []boxOption.RuleSet) bool {
	return common.Any(ruleSets, func(ruleSet boxOption.RuleSet) bool {
		return ruleSet.Type == C.RuleSetTypeRemote
	})
}

func (t *Template) renderRuleSet(metadata M.Metadata, ruleSets []option.RuleSet) []boxOption.RuleSet {
	var result []boxOption.RuleSet
	useHTTPClients := supportsHTTPClients(metadata)
	for _, ruleSet := range ruleSets {
		if ruleSet.Type == constant.RuleSetTypeGitHub {
			var (
				downloadURL    string
				downloadDetour string
				branchSplit    string
			)
			if t.EnableJSDelivr {
				downloadURL = "https://testingcf.jsdelivr.net/gh/"
				if t.DirectTag != "" {
					downloadDetour = t.DirectTag
				} else {
					downloadDetour = DefaultDirectTag
				}
				branchSplit = "@"
			} else {
				downloadURL = "https://raw.githubusercontent.com/"
				branchSplit = "/"
			}

			for _, code := range ruleSet.GitHubOptions.RuleSet {
				result = append(result, boxOption.RuleSet{
					Type:   C.RuleSetTypeRemote,
					Tag:    ruleSet.GitHubOptions.Prefix + code,
					Format: C.RuleSetFormatBinary,
					RemoteOptions: boxOption.RemoteRuleSet{
						URL: downloadURL +
							ruleSet.GitHubOptions.Repository +
							branchSplit +
							ruleSet.GitHubOptions.Path +
							code + ".srs",
					},
				})
				applyRemoteRuleSetHTTPClient(result[len(result)-1:], useHTTPClients, downloadDetour)
			}
		} else {
			result = append(result, ruleSet.DefaultOptions)
		}
	}
	normalizeRemoteRuleSetHTTPClients(result, useHTTPClients)
	return result
}

func supportsHTTPClients(metadata M.Metadata) bool {
	return metadata.Version == nil || metadata.Version.GreaterThanOrEqual(semver.ParseVersion("1.14.0-alpha.13"))
}

func applyRemoteRuleSetHTTPClient(ruleSets []boxOption.RuleSet, useHTTPClients bool, downloadDetour string) {
	if downloadDetour == "" {
		return
	}
	for index := range ruleSets {
		if ruleSets[index].Type != C.RuleSetTypeRemote {
			continue
		}
		if useHTTPClients {
			ruleSets[index].RemoteOptions.HTTPClient = &boxOption.HTTPClientOptions{
				DialerOptions: boxOption.DialerOptions{
					Detour: downloadDetour,
				},
			}
		} else {
			ruleSets[index].RemoteOptions.DownloadDetour = downloadDetour
		}
	}
}

func normalizeRemoteRuleSetHTTPClients(ruleSets []boxOption.RuleSet, useHTTPClients bool) {
	if !useHTTPClients {
		return
	}
	for index := range ruleSets {
		if ruleSets[index].Type != C.RuleSetTypeRemote {
			continue
		}
		remoteOptions := &ruleSets[index].RemoteOptions
		if remoteOptions.DownloadDetour == "" || remoteOptions.HTTPClient != nil {
			continue
		}
		remoteOptions.HTTPClient = &boxOption.HTTPClientOptions{
			DialerOptions: boxOption.DialerOptions{
				Detour: remoteOptions.DownloadDetour,
			},
		}
		remoteOptions.DownloadDetour = ""
	}
}
