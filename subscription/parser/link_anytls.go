package parser

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

func ParseAnyTLSLink(link string) (option.Outbound, error) {
	linkURL, err := url.Parse(link)
	if err != nil {
		return option.Outbound{}, err
	}
	if linkURL.User == nil {
		return option.Outbound{}, E.New("missing password")
	}
	if linkURL.Hostname() == "" {
		return option.Outbound{}, E.New("missing server")
	}

	var options option.AnyTLSOutboundOptions
	options.ServerOptions.Server = linkURL.Hostname()
	options.ServerOptions.ServerPort = portFromString(linkURL.Port())
	options.Password = linkURL.User.Username()
	if password, hasPassword := linkURL.User.Password(); hasPassword {
		options.Password = password
	}
	if options.Password == "" {
		return option.Outbound{}, E.New("missing password")
	}

	query := linkURL.Query()
	options.OutboundTLSOptionsContainer.TLS = anyTLSTLSOptions(query)
	if interval, err := parseDurationQuery(query, "idle_session_check_interval", "idle-session-check-interval"); err != nil {
		return option.Outbound{}, E.Cause(err, "parse idle_session_check_interval")
	} else {
		options.IdleSessionCheckInterval = interval
	}
	if timeout, err := parseDurationQuery(query, "idle_session_timeout", "idle-session-timeout"); err != nil {
		return option.Outbound{}, E.Cause(err, "parse idle_session_timeout")
	} else {
		options.IdleSessionTimeout = timeout
	}
	options.MinIdleSession = parseIntQueryWithKeys(query, 0, "min_idle_session", "min-idle-session")

	var outbound option.Outbound
	outbound.Type = C.TypeAnyTLS
	outbound.Tag = linkURL.Fragment
	outbound.Options = &options
	return outbound, nil
}

func anyTLSTLSOptions(query url.Values) *option.OutboundTLSOptions {
	tlsOptions := &option.OutboundTLSOptions{
		Enabled:  true,
		Insecure: parseBoolQueryWithKeys(query, false, "insecure", "allowInsecure", "skip-cert-verify"),
	}
	if serverName := queryValue(query, "sni", "server_name", "serverName"); serverName != "" {
		tlsOptions.ServerName = serverName
	}
	if alpn := parseListQuery(queryValue(query, "alpn")); len(alpn) > 0 {
		tlsOptions.ALPN = badoption.Listable[string](alpn)
	}
	if fingerprint := queryValue(query, "fp", "fingerprint", "client-fingerprint", "client_fingerprint"); fingerprint != "" {
		tlsOptions.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: fingerprint,
		}
	}
	if echConfig := parseListQuery(queryValue(query, "ech", "ech_config", "ech-config")); len(echConfig) > 0 {
		tlsOptions.ECH = &option.OutboundECHOptions{
			Enabled: true,
			Config:  badoption.Listable[string](echConfig),
		}
	}
	if echConfigPath := queryValue(query, "ech_config_path", "ech-config-path"); echConfigPath != "" {
		if tlsOptions.ECH == nil {
			tlsOptions.ECH = &option.OutboundECHOptions{Enabled: true}
		}
		tlsOptions.ECH.ConfigPath = echConfigPath
	}
	if echQueryServerName := queryValue(query, "ech_query_server_name", "ech-query-server-name"); echQueryServerName != "" {
		if tlsOptions.ECH == nil {
			tlsOptions.ECH = &option.OutboundECHOptions{Enabled: true}
		}
		tlsOptions.ECH.QueryServerName = echQueryServerName
	}
	return tlsOptions
}

func queryValue(query url.Values, keys ...string) string {
	for _, key := range keys {
		if value := query.Get(key); value != "" {
			return value
		}
	}
	return ""
}

func parseIntQueryWithKeys(query url.Values, defaultValue int, keys ...string) int {
	for _, key := range keys {
		if val := query.Get(key); val != "" {
			if parsed, err := strconv.Atoi(val); err == nil {
				return parsed
			}
		}
	}
	return defaultValue
}

func parseBoolQueryWithKeys(query url.Values, defaultValue bool, keys ...string) bool {
	for _, key := range keys {
		if val := query.Get(key); val != "" {
			if parsed, err := strconv.ParseBool(val); err == nil {
				return parsed
			}
			if parsed, err := strconv.Atoi(val); err == nil {
				return parsed != 0
			}
		}
	}
	return defaultValue
}

func parseListQuery(value string) []string {
	if value == "" {
		return nil
	}
	items := strings.Split(value, ",")
	result := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}

func parseDurationQuery(query url.Values, keys ...string) (badoption.Duration, error) {
	value := queryValue(query, keys...)
	if value == "" {
		return 0, nil
	}
	var duration badoption.Duration
	err := duration.UnmarshalJSON([]byte(strconv.Quote(value)))
	if err != nil {
		err = json.Unmarshal([]byte(value), &duration)
	}
	return duration, err
}
