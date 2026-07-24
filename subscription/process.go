package subscription

import (
	"regexp"
	"strings"

	"github.com/sagernet/serenity/option"
	boxOption "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

type ProcessOptions struct {
	option.OutboundProcessOptions
	filter       []*regexp.Regexp
	filterServer []*regexp.Regexp
	exclude      []*regexp.Regexp
	rename       []*Rename
}

type Rename struct {
	From *regexp.Regexp
	To   string
}

func NewProcessOptions(options option.OutboundProcessOptions) (*ProcessOptions, error) {
	var (
		filter       []*regexp.Regexp
		filterServer []*regexp.Regexp
		exclude      []*regexp.Regexp
		rename       []*Rename
	)
	for regexIndex, it := range options.Filter {
		regex, err := regexp.Compile(it)
		if err != nil {
			return nil, E.Cause(err, "parse filter[", regexIndex, "]")
		}
		filter = append(filter, regex)
	}
	for regexIndex, it := range options.FilterServer {
		regex, err := regexp.Compile(it)
		if err != nil {
			return nil, E.Cause(err, "parse filter_server[", regexIndex, "]")
		}
		filterServer = append(filterServer, regex)
	}
	for regexIndex, it := range options.Exclude {
		regex, err := regexp.Compile(it)
		if err != nil {
			return nil, E.Cause(err, "parse exclude[", regexIndex, "]")
		}
		exclude = append(exclude, regex)
	}
	if options.Rename != nil {
		for renameIndex, entry := range options.Rename.Entries() {
			regex, err := regexp.Compile(entry.Key)
			if err != nil {
				return nil, E.Cause(err, "parse rename[", renameIndex, "]: parse ", entry.Key)
			}
			rename = append(rename, &Rename{
				From: regex,
				To:   entry.Value,
			})
		}
	}
	return &ProcessOptions{
		OutboundProcessOptions: options,
		filter:                 filter,
		filterServer:           filterServer,
		exclude:                exclude,
		rename:                 rename,
	}, nil
}

func (o *ProcessOptions) Process(outbounds []boxOption.Outbound) []boxOption.Outbound {
	newOutbounds := make([]boxOption.Outbound, 0, len(outbounds))
	renameResult := make(map[string]string)
	for _, outbound := range outbounds {
		inProcess := o.matches(outbound.Tag, outbound.Type, serverOf(outbound.Options))
		if o.Invert {
			inProcess = !inProcess
		}
		if !inProcess {
			newOutbounds = append(newOutbounds, outbound)
			continue
		}
		if o.Remove {
			continue
		}
		originTag := outbound.Tag
		if len(o.rename) > 0 {
			for _, rename := range o.rename {
				outbound.Tag = rename.From.ReplaceAllString(outbound.Tag, rename.To)
			}
		}
		if o.RemoveEmoji {
			outbound.Tag = removeEmojis(outbound.Tag)
		}
		outbound.Tag = strings.TrimSpace(outbound.Tag)
		if originTag != outbound.Tag {
			renameResult[originTag] = outbound.Tag
		}
		if o.RewriteMultiplex != nil {
			switch outboundOptions := outbound.Options.(type) {
			case *boxOption.ShadowsocksOutboundOptions:
				outboundOptions.Multiplex = o.RewriteMultiplex
			case *boxOption.TrojanOutboundOptions:
				outboundOptions.Multiplex = o.RewriteMultiplex
			case *boxOption.VMessOutboundOptions:
				outboundOptions.Multiplex = o.RewriteMultiplex
			case *boxOption.VLESSOutboundOptions:
				outboundOptions.Multiplex = o.RewriteMultiplex
			}
		}

		if o.RewriteDialerOptions != nil {
			if dialerOptionsWrapper, containsDialerOptions := outbound.Options.(boxOption.DialerOptionsWrapper); containsDialerOptions {
				dialerOptionsWrapper.ReplaceDialerOptions(*o.RewriteDialerOptions)
			}
		}
		if o.RewriteTLS != nil {
			if tlsOptionsWrapper, containsTLSOptions := outbound.Options.(boxOption.OutboundTLSOptionsWrapper); containsTLSOptions {
				tlsOptionsWrapper.ReplaceOutboundTLSOptions(o.RewriteTLS)
			}
		}
		if o.RewriteVMessOptions != nil {
			if outboundOptions, ok := outbound.Options.(*boxOption.VMessOutboundOptions); ok {
				if o.RewriteVMessOptions.Security != "" {
					outboundOptions.Security = o.RewriteVMessOptions.Security
				}
			}
		}

		if o.RewritePacketEncoding != "" {
			switch outboundOptions := outbound.Options.(type) {
			case *boxOption.VMessOutboundOptions:
				outboundOptions.PacketEncoding = o.RewritePacketEncoding
			case *boxOption.VLESSOutboundOptions:
				outboundOptions.PacketEncoding = &o.RewritePacketEncoding
			}
		}

		if o.RewriteUTLS != nil {
			switch outboundOptions := outbound.Options.(type) {
			case *boxOption.VMessOutboundOptions:
				if outboundOptions.TLS == nil {
					outboundOptions.TLS = &boxOption.OutboundTLSOptions{}
				}
				if o.RewriteUTLS.Enabled {
					outboundOptions.TLS.UTLS = &boxOption.OutboundUTLSOptions{
						Enabled:     true,
						Fingerprint: o.RewriteUTLS.Fingerprint,
					}
				} else if outboundOptions.TLS.UTLS != nil {
					outboundOptions.TLS.UTLS = nil
				}
			case *boxOption.VLESSOutboundOptions:
				if outboundOptions.TLS == nil {
					outboundOptions.TLS = &boxOption.OutboundTLSOptions{}
				}
				if o.RewriteUTLS.Enabled {
					outboundOptions.TLS.UTLS = &boxOption.OutboundUTLSOptions{
						Enabled:     true,
						Fingerprint: o.RewriteUTLS.Fingerprint,
					}
				} else if outboundOptions.TLS.UTLS != nil {
					outboundOptions.TLS.UTLS = nil
				}
			case *boxOption.TrojanOutboundOptions:
				if outboundOptions.TLS == nil {
					outboundOptions.TLS = &boxOption.OutboundTLSOptions{}
				}
				if o.RewriteUTLS.Enabled {
					outboundOptions.TLS.UTLS = &boxOption.OutboundUTLSOptions{
						Enabled:     true,
						Fingerprint: o.RewriteUTLS.Fingerprint,
					}
				} else if outboundOptions.TLS.UTLS != nil {
					outboundOptions.TLS.UTLS = nil
				}
			case *boxOption.AnyTLSOutboundOptions:
				if outboundOptions.TLS == nil {
					outboundOptions.TLS = &boxOption.OutboundTLSOptions{}
				}
				if o.RewriteUTLS.Enabled {
					outboundOptions.TLS.UTLS = &boxOption.OutboundUTLSOptions{
						Enabled:     true,
						Fingerprint: o.RewriteUTLS.Fingerprint,
					}
				} else if outboundOptions.TLS.UTLS != nil {
					outboundOptions.TLS.UTLS = nil
				}
			}
		}

		newOutbounds = append(newOutbounds, outbound)
	}
	if len(renameResult) > 0 {
		for i, outbound := range newOutbounds {
			if dialerOptionsWrapper, containsDialerOptions := outbound.Options.(boxOption.DialerOptionsWrapper); containsDialerOptions {
				dialerOptions := dialerOptionsWrapper.TakeDialerOptions()
				if dialerOptions.Detour == "" {
					continue
				}
				newTag, loaded := renameResult[dialerOptions.Detour]
				if !loaded {
					continue
				}
				dialerOptions.Detour = newTag
				dialerOptionsWrapper.ReplaceDialerOptions(dialerOptions)
				newOutbounds[i] = outbound
			}
		}
	}
	return newOutbounds
}

func (o *ProcessOptions) ProcessEndpoints(endpoints []boxOption.Endpoint) []boxOption.Endpoint {
	newEndpoints := make([]boxOption.Endpoint, 0, len(endpoints))
	renameResult := make(map[string]string)
	for _, endpoint := range endpoints {
		inProcess := o.matches(endpoint.Tag, endpoint.Type, serverOf(endpoint.Options))
		if o.Invert {
			inProcess = !inProcess
		}
		if !inProcess {
			newEndpoints = append(newEndpoints, endpoint)
			continue
		}
		if o.Remove {
			continue
		}
		originTag := endpoint.Tag
		for _, rename := range o.rename {
			endpoint.Tag = rename.From.ReplaceAllString(endpoint.Tag, rename.To)
		}
		if o.RemoveEmoji {
			endpoint.Tag = removeEmojis(endpoint.Tag)
		}
		endpoint.Tag = strings.TrimSpace(endpoint.Tag)
		if originTag != endpoint.Tag {
			renameResult[originTag] = endpoint.Tag
		}
		newEndpoints = append(newEndpoints, endpoint)
	}
	if len(renameResult) > 0 {
		for i, endpoint := range newEndpoints {
			if dialerOptionsWrapper, ok := endpoint.Options.(boxOption.DialerOptionsWrapper); ok {
				dialerOptions := dialerOptionsWrapper.TakeDialerOptions()
				if newTag, loaded := renameResult[dialerOptions.Detour]; loaded {
					dialerOptions.Detour = newTag
					dialerOptionsWrapper.ReplaceDialerOptions(dialerOptions)
					newEndpoints[i] = endpoint
				}
			}
		}
	}
	return newEndpoints
}

func (o *ProcessOptions) RenameMap(outbounds []boxOption.Outbound, endpoints []boxOption.Endpoint) map[string]string {
	if o.Remove {
		return nil
	}
	result := make(map[string]string)
	apply := func(tag string, itemType string, server string) {
		matched := o.matches(tag, itemType, server)
		if o.Invert {
			matched = !matched
		}
		if !matched {
			return
		}
		newTag := tag
		for _, rename := range o.rename {
			newTag = rename.From.ReplaceAllString(newTag, rename.To)
		}
		if o.RemoveEmoji {
			newTag = removeEmojis(newTag)
		}
		newTag = strings.TrimSpace(newTag)
		if tag != newTag {
			result[tag] = newTag
		}
	}
	for _, outbound := range outbounds {
		apply(outbound.Tag, outbound.Type, serverOf(outbound.Options))
	}
	for _, endpoint := range endpoints {
		apply(endpoint.Tag, endpoint.Type, serverOf(endpoint.Options))
	}
	return result
}

func RewriteRenamedDetours(outbounds []boxOption.Outbound, endpoints []boxOption.Endpoint, renameMap map[string]string) {
	if len(renameMap) == 0 {
		return
	}
	for _, outbound := range outbounds {
		if wrapper, ok := outbound.Options.(boxOption.DialerOptionsWrapper); ok {
			rewriteRenamedDetour(wrapper, renameMap)
		}
	}
	for _, endpoint := range endpoints {
		if wrapper, ok := endpoint.Options.(boxOption.DialerOptionsWrapper); ok {
			rewriteRenamedDetour(wrapper, renameMap)
		}
	}
}

func rewriteRenamedDetour(wrapper boxOption.DialerOptionsWrapper, renameMap map[string]string) {
	dialerOptions := wrapper.TakeDialerOptions()
	if renamed, loaded := renameMap[dialerOptions.Detour]; loaded {
		dialerOptions.Detour = renamed
		wrapper.ReplaceDialerOptions(dialerOptions)
	}
}

func (o *ProcessOptions) matches(tag string, itemType string, server string) bool {
	if len(o.filter) == 0 && len(o.filterServer) == 0 && len(o.FilterType) == 0 && len(o.exclude) == 0 && len(o.ExcludeType) == 0 {
		return true
	}
	if len(o.filter) > 0 && common.Any(o.filter, func(it *regexp.Regexp) bool { return it.MatchString(tag) }) {
		return true
	}
	if server != "" && len(o.filterServer) > 0 && common.Any(o.filterServer, func(it *regexp.Regexp) bool { return it.MatchString(server) }) {
		return true
	}
	if len(o.FilterType) > 0 && common.Contains(o.FilterType, itemType) {
		return true
	}
	if len(o.exclude) > 0 && !common.Any(o.exclude, func(it *regexp.Regexp) bool { return it.MatchString(tag) }) {
		return true
	}
	return len(o.ExcludeType) > 0 && !common.Contains(o.ExcludeType, itemType)
}

func serverOf(options any) string {
	serverOptions, ok := options.(boxOption.ServerOptionsWrapper)
	if !ok {
		return ""
	}
	return serverOptions.TakeServerOptions().Server
}

func removeEmojis(s string) string {
	var runes []rune
	for _, r := range s {
		if !(r >= 0x1F600 && r <= 0x1F64F || // Emoticons
			r >= 0x1F300 && r <= 0x1F5FF || // Symbols & Pictographs
			r >= 0x1F680 && r <= 0x1F6FF || // Transport & Map Symbols
			r >= 0x1F1E0 && r <= 0x1F1FF || // Flags
			r >= 0x2600 && r <= 0x26FF || // Misc symbols
			r >= 0x2700 && r <= 0x27BF || // Dingbats
			r >= 0xFE00 && r <= 0xFE0F || // Variation Selectors
			r >= 0x1F900 && r <= 0x1F9FF || // Supplemental Symbols and Pictographs
			r >= 0x1F018 && r <= 0x1F270 || // Various asian characters
			r >= 0x238C && r <= 0x2454 || // Misc items
			r >= 0x20D0 && r <= 0x20FF) { // Combining Diacritical Marks for Symbols
			runes = append(runes, r)
		}
	}
	return string(runes)
}
