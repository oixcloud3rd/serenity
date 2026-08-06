package parser

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"net/netip"
	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badoption"
	N "github.com/sagernet/sing/common/network"

	"github.com/metacubex/mihomo/adapter"
	clash_outbound "github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/structure"
	clash_utils "github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/constant"
)

func ParseClashSubscription(_ context.Context, content string) (Result, error) {
	config, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		return Result{}, E.Cause(err, "parse clash config")
	}
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
	var result Result
	var conversionErr error
	for i, proxyMapping := range config.Proxy {
		rawType := strings.ToLower(strings.TrimSpace(format.ToString(proxyMapping["type"])))
		rawName := strings.TrimSpace(format.ToString(proxyMapping["name"]))
		switch rawType {
		case "wireguard":
			clashOption := &clash_outbound.WireGuardOption{}
			err = decoder.Decode(proxyMapping, clashOption)
			var endpoint option.Endpoint
			if err == nil {
				endpoint, err = clashWireGuardEndpoint(clashOption)
			}
			if err == nil {
				result.Endpoints = append(result.Endpoints, endpoint)
			} else {
				conversionErr = E.Errors(conversionErr, E.Cause(err, "convert proxy ", rawName, " (WireGuard)"))
			}
			continue
		case "openvpn":
			clashOption := &clash_outbound.OpenVPNOption{}
			err = decoder.Decode(proxyMapping, clashOption)
			if err == nil {
				var endpoint option.Endpoint
				endpoint, err = clashOpenVPNEndpoint(clashOption)
				if err == nil {
					result.Endpoints = append(result.Endpoints, endpoint)
				}
			} else {
				conversionErr = E.Errors(conversionErr, E.Cause(err, "convert proxy ", rawName, " (OpenVPN)"))
			}
			continue
		case "tailscale":
			clashOption := &clash_outbound.TailscaleOption{}
			err = decoder.Decode(proxyMapping, clashOption)
			if err == nil {
				var endpoint option.Endpoint
				endpoint, err = clashTailscaleEndpoint(clashOption)
				if err == nil {
					result.Endpoints = append(result.Endpoints, endpoint)
				}
			} else {
				conversionErr = E.Errors(conversionErr, E.Cause(err, "convert proxy ", rawName, " (Tailscale)"))
			}
			continue
		case "dns", "gost-relay", "masque", "mieru", "ssr", "sudoku", "trusttunnel":
			conversionErr = E.Errors(conversionErr, E.New("unsupported proxy type ", rawType))
			continue
		}
		proxy, err := adapter.ParseProxy(proxyMapping)
		if err != nil {
			conversionErr = E.Errors(conversionErr, E.Cause(err, "parse proxy ", i))
			continue
		}
		var outbound option.Outbound
		outbound.Tag = proxy.Name()
		switch proxy.Type() {
		case constant.Direct:
			directOption := &clash_outbound.DirectOption{}
			err = decoder.Decode(proxyMapping, directOption)
			outbound.Type = C.TypeDirect
			outbound.Options = &option.DirectOutboundOptions{DialerOptions: clashDialerOptions(directOption.BasicOption)}
		case constant.Reject, constant.RejectDrop:
			outbound.Type = C.TypeBlock
			outbound.Options = &option.StubOptions{}
		case constant.Shadowsocks:
			ssOption := &clash_outbound.ShadowSocksOption{}
			err = decoder.Decode(proxyMapping, ssOption)
			outbound.Type = C.TypeShadowsocks
			outbound.Options = &option.ShadowsocksOutboundOptions{
				DialerOptions: clashDialerOptions(ssOption.BasicOption),
				ServerOptions: option.ServerOptions{
					Server:     ssOption.Server,
					ServerPort: uint16(ssOption.Port),
				},
				Password:      ssOption.Password,
				Method:        clashShadowsocksCipher(ssOption.Cipher),
				Plugin:        clashPluginName(ssOption.Plugin),
				PluginOptions: clashPluginOptions(ssOption.Plugin, ssOption.PluginOpts),
				Network:       clashNetworks(ssOption.UDP),
			}
		case constant.AnyTLS:
			clashOption := &clash_outbound.AnyTLSOption{}
			err = decoder.Decode(proxyMapping, clashOption)
			if err == nil {
				err = validateClashCertificateFingerprint(clashOption.Fingerprint)
			}
			tlsOptions := clashTLSOptions(true, clashOption.SNI, clashOption.SkipCertVerify, clashOption.ALPN, clashOption.ClientFingerprint, clashOption.Certificate, clashOption.PrivateKey, clashOption.ECHOpts, clash_outbound.RealityOptions{})
			outbound.Type = C.TypeAnyTLS
			outbound.Options = &option.AnyTLSOutboundOptions{
				DialerOptions:               clashDialerOptions(clashOption.BasicOption),
				ServerOptions:               option.ServerOptions{Server: clashOption.Server, ServerPort: uint16(clashOption.Port)},
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOptions},
				Password:                    clashOption.Password,
				IdleSessionCheckInterval:    badoption.Duration(time.Duration(clashOption.IdleSessionCheckInterval) * time.Second),
				IdleSessionTimeout:          badoption.Duration(time.Duration(clashOption.IdleSessionTimeout) * time.Second),
				MinIdleSession:              clashOption.MinIdleSession,
			}
		case constant.Trojan:
			trojanOption := &clash_outbound.TrojanOption{}
			err = decoder.Decode(proxyMapping, trojanOption)
			if err == nil {
				err = validateClashCertificateFingerprint(trojanOption.Fingerprint)
			}
			if err == nil {
				err = validateClashTransport(trojanOption.Network)
			}
			if err == nil && trojanOption.SSOpts.Enabled {
				err = E.New("Trojan Shadowsocks layer is not supported by target sing-box")
			}
			outbound.Type = C.TypeTrojan
			outbound.Options = &option.TrojanOutboundOptions{
				DialerOptions: clashDialerOptions(trojanOption.BasicOption),
				ServerOptions: option.ServerOptions{
					Server:     trojanOption.Server,
					ServerPort: uint16(trojanOption.Port),
				},
				Password:                    trojanOption.Password,
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: clashTLSOptions(true, trojanOption.SNI, trojanOption.SkipCertVerify, trojanOption.ALPN, trojanOption.ClientFingerprint, trojanOption.Certificate, trojanOption.PrivateKey, trojanOption.ECHOpts, trojanOption.RealityOpts)},
				Transport:                   clashTransport(trojanOption.Network, clash_outbound.HTTPOptions{}, clash_outbound.HTTP2Options{}, trojanOption.GrpcOpts, trojanOption.WSOpts),
				Network:                     clashNetworks(trojanOption.UDP),
			}
		case constant.Vmess:
			vmessOption := &clash_outbound.VmessOption{}
			err = decoder.Decode(proxyMapping, vmessOption)
			if err == nil {
				err = validateClashCertificateFingerprint(vmessOption.Fingerprint)
			}
			if err == nil {
				err = validateClashTransport(vmessOption.Network)
			}
			outbound.Type = C.TypeVMess
			outbound.Options = &option.VMessOutboundOptions{
				DialerOptions: clashDialerOptions(vmessOption.BasicOption),
				ServerOptions: option.ServerOptions{
					Server:     vmessOption.Server,
					ServerPort: uint16(vmessOption.Port),
				},
				UUID:                        vmessOption.UUID,
				Security:                    vmessOption.Cipher,
				AlterId:                     vmessOption.AlterID,
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: clashTLSOptions(vmessOption.TLS || vmessOption.RealityOpts.PublicKey != "", vmessOption.ServerName, vmessOption.SkipCertVerify, vmessOption.ALPN, vmessOption.ClientFingerprint, vmessOption.Certificate, vmessOption.PrivateKey, vmessOption.ECHOpts, vmessOption.RealityOpts)},
				Transport:                   clashTransport(vmessOption.Network, vmessOption.HTTPOpts, vmessOption.HTTP2Opts, vmessOption.GrpcOpts, vmessOption.WSOpts),
				Network:                     clashNetworks(vmessOption.UDP),
				PacketEncoding:              clashPacketEncoding(vmessOption.PacketEncoding, vmessOption.PacketAddr, vmessOption.XUDP),
				GlobalPadding:               vmessOption.GlobalPadding,
				AuthenticatedLength:         vmessOption.AuthenticatedLength,
			}
		case constant.Vless:
			clashOption := &clash_outbound.VlessOption{}
			err = decoder.Decode(proxyMapping, clashOption)
			if err == nil {
				err = validateClashCertificateFingerprint(clashOption.Fingerprint)
			}
			if err == nil {
				err = validateClashTransport(clashOption.Network)
			}
			if err == nil && clashOption.Encryption != "" {
				err = E.New("VLESS encryption is not supported by target sing-box")
			}
			outbound.Type = C.TypeVLESS
			outbound.Options = &option.VLESSOutboundOptions{
				DialerOptions:               clashDialerOptions(clashOption.BasicOption),
				ServerOptions:               option.ServerOptions{Server: clashOption.Server, ServerPort: uint16(clashOption.Port)},
				UUID:                        clashOption.UUID,
				Flow:                        clashOption.Flow,
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: clashTLSOptions(clashOption.TLS || clashOption.RealityOpts.PublicKey != "", clashOption.ServerName, clashOption.SkipCertVerify, clashOption.ALPN, clashOption.ClientFingerprint, clashOption.Certificate, clashOption.PrivateKey, clashOption.ECHOpts, clashOption.RealityOpts)},
				Transport:                   clashTransport(clashOption.Network, clashOption.HTTPOpts, clashOption.HTTP2Opts, clashOption.GrpcOpts, clashOption.WSOpts),
				Network:                     clashNetworks(clashOption.UDP),
				PacketEncoding:              optionalString(clashPacketEncoding(clashOption.PacketEncoding, clashOption.PacketAddr, clashOption.XUDP)),
			}
		case constant.Socks5:
			socks5Option := &clash_outbound.Socks5Option{}
			err = decoder.Decode(proxyMapping, socks5Option)

			if err == nil && socks5Option.TLS {
				err = E.New("SOCKS5 TLS is not supported by target sing-box")
			}

			outbound.Type = C.TypeSOCKS
			outbound.Options = &option.SOCKSOutboundOptions{
				DialerOptions: clashDialerOptions(socks5Option.BasicOption),
				ServerOptions: option.ServerOptions{
					Server:     socks5Option.Server,
					ServerPort: uint16(socks5Option.Port),
				},
				Username: socks5Option.UserName,
				Password: socks5Option.Password,
				Network:  clashNetworks(socks5Option.UDP),
			}
		case constant.Http:
			httpOption := &clash_outbound.HttpOption{}
			err = decoder.Decode(proxyMapping, httpOption)
			if err == nil {
				err = validateClashCertificateFingerprint(httpOption.Fingerprint)
			}

			outbound.Type = C.TypeHTTP
			outbound.Options = &option.HTTPOutboundOptions{
				DialerOptions: clashDialerOptions(httpOption.BasicOption),
				ServerOptions: option.ServerOptions{
					Server:     httpOption.Server,
					ServerPort: uint16(httpOption.Port),
				},
				Username:                    httpOption.UserName,
				Password:                    httpOption.Password,
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: clashTLSOptions(httpOption.TLS, httpOption.SNI, httpOption.SkipCertVerify, nil, "", httpOption.Certificate, httpOption.PrivateKey, clash_outbound.ECHOptions{}, clash_outbound.RealityOptions{})},
				Headers:                     clashHTTPHeaders(httpOption.Headers),
			}
		case constant.Hysteria:
			clashOption := &clash_outbound.HysteriaOption{}
			err = decoder.Decode(proxyMapping, clashOption)
			if err == nil {
				err = validateClashCertificateFingerprint(clashOption.Fingerprint)
			}
			if err == nil && clashOption.Protocol != "" && clashOption.Protocol != "udp" {
				err = E.New("Hysteria transport protocol ", clashOption.Protocol, " is not supported by target sing-box")
			}
			if err == nil && clashOption.ObfsProtocol != "" {
				err = E.New("Hysteria obfs-protocol is not supported by target sing-box")
			}
			var auth []byte
			if err == nil && clashOption.Auth != "" {
				auth, err = base64.StdEncoding.DecodeString(clashOption.Auth)
			}
			if clashOption.Auth == "" {
				auth = []byte(clashOption.AuthString)
			}
			upMbps, downMbps := clashOption.UpSpeed, clashOption.DownSpeed
			if err == nil && (upMbps == 0 || downMbps == 0) {
				var up, down uint64
				up, down, err = clashOption.Speed()
				if upMbps == 0 {
					upMbps = int(up / 125000)
				}
				if downMbps == 0 {
					downMbps = int(down / 125000)
				}
			}
			outbound.Type = C.TypeHysteria
			outbound.Options = &option.HysteriaOutboundOptions{
				DialerOptions: clashDialerOptions(clashOption.BasicOption),
				ServerOptions: option.ServerOptions{Server: clashOption.Server, ServerPort: uint16(clashOption.Port)},
				ServerPorts:   optionalList(clashOption.Ports),
				HopInterval:   badoption.Duration(time.Duration(clashOption.HopInterval) * time.Second),
				UpMbps:        upMbps, DownMbps: downMbps, Obfs: clashOption.Obfs, Auth: auth, AuthString: clashOption.AuthString,
				ReceiveWindowConn: uint64(clashOption.ReceiveWindowConn), ReceiveWindow: uint64(clashOption.ReceiveWindow), DisableMTUDiscovery: clashOption.DisableMTUDiscovery,
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: clashTLSOptions(true, clashOption.SNI, clashOption.SkipCertVerify, clashOption.ALPN, "", clashOption.Certificate, clashOption.PrivateKey, clashOption.ECHOpts, clash_outbound.RealityOptions{})},
			}
		case constant.Hysteria2:
			clashOption := &clash_outbound.Hysteria2Option{}
			err = decoder.Decode(proxyMapping, clashOption)
			if err == nil {
				err = validateClashCertificateFingerprint(clashOption.Fingerprint)
			}
			if err == nil && clashOption.RealmOpts.Enable {
				err = validateClashCertificateFingerprint(clashOption.RealmOpts.Fingerprint)
			}
			var hopInterval badoption.Duration
			if err == nil {
				hopInterval, err = parseOptionalDuration(clashOption.HopInterval)
			}
			var obfs *option.Hysteria2Obfs
			if clashOption.Obfs != "" {
				obfs = &option.Hysteria2Obfs{Type: clashOption.Obfs, Password: clashOption.ObfsPassword}
			}
			var realm *option.Hysteria2Realm
			if clashOption.RealmOpts.Enable {
				realm = &option.Hysteria2Realm{
					ServerURL:   clashOption.RealmOpts.ServerURL,
					Token:       clashOption.RealmOpts.Token,
					RealmID:     clashOption.RealmOpts.RealmID,
					STUNServers: clashOption.RealmOpts.STUNServers,
					HTTPClient:  &option.HTTPClientOptions{OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: clashTLSOptions(true, clashOption.RealmOpts.SNI, clashOption.RealmOpts.SkipCertVerify, clashOption.RealmOpts.ALPN, "", clashOption.RealmOpts.Certificate, clashOption.RealmOpts.PrivateKey, clash_outbound.ECHOptions{}, clash_outbound.RealityOptions{})}},
				}
			}
			outbound.Type = C.TypeHysteria2
			outbound.Options = &option.Hysteria2OutboundOptions{
				DialerOptions: clashDialerOptions(clashOption.BasicOption), ServerOptions: option.ServerOptions{Server: clashOption.Server, ServerPort: uint16(clashOption.Port)},
				ServerPorts: optionalList(clashOption.Ports), HopInterval: hopInterval, UpMbps: speedMbps(clashOption.Up), DownMbps: speedMbps(clashOption.Down), Password: clashOption.Password, Obfs: obfs,
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: clashTLSOptions(true, clashOption.SNI, clashOption.SkipCertVerify, clashOption.ALPN, "", clashOption.Certificate, clashOption.PrivateKey, clashOption.ECHOpts, clash_outbound.RealityOptions{})},
				BBRProfile:                  clashOption.BBRProfile, Realm: realm,
			}
		case constant.Tuic:
			clashOption := &clash_outbound.TuicOption{}
			err = decoder.Decode(proxyMapping, clashOption)
			if err == nil {
				err = validateClashCertificateFingerprint(clashOption.Fingerprint)
			}
			if err == nil && clashOption.Token != "" && clashOption.UUID == "" {
				err = E.New("legacy TUIC token authentication is not supported by target sing-box")
			}
			tlsOptions := clashTLSOptions(true, clashOption.SNI, clashOption.SkipCertVerify, clashOption.ALPN, "", clashOption.Certificate, clashOption.PrivateKey, clashOption.ECHOpts, clash_outbound.RealityOptions{})
			tlsOptions.DisableSNI = clashOption.DisableSni
			outbound.Type = C.TypeTUIC
			outbound.Options = &option.TUICOutboundOptions{
				DialerOptions: clashDialerOptions(clashOption.BasicOption), ServerOptions: option.ServerOptions{Server: clashOption.Server, ServerPort: uint16(clashOption.Port)},
				UUID: clashOption.UUID, Password: clashOption.Password, CongestionControl: clashOption.CongestionController, UDPRelayMode: clashOption.UdpRelayMode, UDPOverStream: clashOption.UDPOverStream,
				ZeroRTTHandshake: clashOption.ReduceRtt, Heartbeat: badoption.Duration(time.Duration(clashOption.HeartbeatInterval) * time.Millisecond),
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: tlsOptions},
			}
		case constant.Ssh:
			clashOption := &clash_outbound.SshOption{}
			err = decoder.Decode(proxyMapping, clashOption)
			outbound.Type = C.TypeSSH
			outbound.Options = &option.SSHOutboundOptions{
				DialerOptions: clashDialerOptions(clashOption.BasicOption), ServerOptions: option.ServerOptions{Server: clashOption.Server, ServerPort: uint16(clashOption.Port)},
				User: clashOption.UserName, Password: clashOption.Password, PrivateKey: optionalList(clashOption.PrivateKey), PrivateKeyPassphrase: clashOption.PrivateKeyPassphrase, HostKey: clashOption.HostKey, HostKeyAlgorithms: clashOption.HostKeyAlgorithms,
			}
		case constant.Snell:
			clashOption := &clash_outbound.SnellOption{}
			err = decoder.Decode(proxyMapping, clashOption)
			if err == nil && clashOption.Version != 4 && clashOption.Version != 6 {
				err = E.New("target sing-box supports Snell outbound versions 4 and 6")
			}
			if err == nil && (clashOption.ShadowTLSPassword != "" || clashOption.ShadowTLSSNI != "" || clashOption.ShadowTLSVersion != 0) {
				err = E.New("Snell ShadowTLS is not supported by target sing-box")
			}
			snellOptions := &option.SnellOutboundOptions{
				Version: clashOption.Version,
				AbstractSnellOutboundOptions: option.AbstractSnellOutboundOptions{
					DialerOptions: clashDialerOptions(clashOption.BasicOption), ServerOptions: option.ServerOptions{Server: clashOption.Server, ServerPort: uint16(clashOption.Port)},
					PSK: clashOption.Psk, Reuse: clashOption.Reuse != nil && *clashOption.Reuse, Network: clashNetworks(clashOption.UDP),
				},
			}
			if clashOption.Identity {
				snellOptions.Identity = 1
			}
			if err == nil {
				err = applySnellObfs(snellOptions, clashOption)
			}
			outbound.Type = C.TypeSnell
			outbound.Options = snellOptions
		case constant.WireGuard:
			clashOption := &clash_outbound.WireGuardOption{}
			err = decoder.Decode(proxyMapping, clashOption)
			var endpoint option.Endpoint
			if err == nil {
				endpoint, err = clashWireGuardEndpoint(clashOption)
			}
			if err == nil {
				result.Endpoints = append(result.Endpoints, endpoint)
			}
		case constant.OpenVPN:
			clashOption := &clash_outbound.OpenVPNOption{}
			err = decoder.Decode(proxyMapping, clashOption)
			var endpoint option.Endpoint
			if err == nil {
				endpoint, err = clashOpenVPNEndpoint(clashOption)
			}
			if err == nil {
				result.Endpoints = append(result.Endpoints, endpoint)
			}
		case constant.Tailscale:
			clashOption := &clash_outbound.TailscaleOption{}
			err = decoder.Decode(proxyMapping, clashOption)
			var endpoint option.Endpoint
			if err == nil {
				endpoint, err = clashTailscaleEndpoint(clashOption)
			}
			if err == nil {
				result.Endpoints = append(result.Endpoints, endpoint)
			}
		case constant.Dns, constant.GostRelay, constant.Masque, constant.Mieru, constant.ShadowsocksR, constant.Sudoku, constant.TrustTunnel:
			err = E.New("unsupported proxy type ", proxy.Type().String())
		default:
			err = E.New("unsupported proxy type ", proxy.Type().String())
		}
		if err != nil {
			conversionErr = E.Errors(conversionErr, E.Cause(err, "convert proxy ", proxy.Name(), " (", proxy.Type().String(), ")"))
			continue
		}
		if outbound.Type != "" {
			result.Outbounds = append(result.Outbounds, outbound)
		}
	}
	if len(result.Outbounds)+len(result.Endpoints) > 0 {
		return result, conversionErr
	}
	return Result{}, E.Cause(conversionErr, "no supported proxies or endpoints found")
}

func clashDialerOptions(basic clash_outbound.BasicOption) option.DialerOptions {
	return option.DialerOptions{
		Detour: basic.DialerProxy,
		AbstractDialerOptions: option.AbstractDialerOptions{
			BindInterface: basic.Interface,
			RoutingMark:   option.FwMark(basic.RoutingMark),
			TCPFastOpen:   basic.TFO,
			TCPMultiPath:  basic.MPTCP,
		},
	}
}

func clashTLSOptions(enabled bool, serverName string, insecure bool, alpn []string, clientFingerprint string, certificate string, privateKey string, ech clash_outbound.ECHOptions, reality clash_outbound.RealityOptions) *option.OutboundTLSOptions {
	if !enabled && reality.PublicKey == "" && !ech.Enable {
		return nil
	}
	tlsOptions := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   insecure,
		ALPN:       alpn,
	}
	if certificate != "" {
		tlsOptions.ClientCertificate = []string{certificate}
	}
	if privateKey != "" {
		tlsOptions.ClientKey = []string{privateKey}
	}
	if clientFingerprint != "" {
		tlsOptions.UTLS = &option.OutboundUTLSOptions{Enabled: true, Fingerprint: clientFingerprint}
	}
	if reality.PublicKey != "" {
		tlsOptions.Reality = &option.OutboundRealityOptions{Enabled: true, PublicKey: reality.PublicKey, ShortID: reality.ShortID}
	}
	if ech.Enable {
		echOptions := &option.OutboundECHOptions{Enabled: true, QueryServerName: ech.QueryServerName}
		if ech.Config != "" {
			if configBytes, err := base64.StdEncoding.DecodeString(ech.Config); err == nil {
				echOptions.Config = encodeECHConfig(configBytes)
			}
		}
		tlsOptions.ECH = echOptions
	}
	return tlsOptions
}

func encodeECHConfig(configBytes []byte) []string {
	content := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "ECH CONFIGS", Bytes: configBytes})))
	return strings.Split(content, "\n")
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func clashPacketEncoding(explicit string, packetAddress bool, xudp bool) string {
	if explicit != "" {
		return explicit
	}
	if xudp {
		return "xudp"
	}
	if packetAddress {
		return "packetaddr"
	}
	return ""
}

func validateClashTransport(network string) error {
	switch network {
	case "", "tcp", "http", "h2", "grpc", "ws":
		return nil
	default:
		return E.New("unsupported V2Ray transport ", network)
	}
}

func validateClashCertificateFingerprint(fingerprint string) error {
	if fingerprint != "" {
		return E.New("Clash certificate fingerprint pinning has no equivalent in target sing-box")
	}
	return nil
}

func optionalList(value string) badoption.Listable[string] {
	if value == "" {
		return nil
	}
	return []string{value}
}

func clashHTTPHeaders(values map[string]string) badoption.HTTPHeader {
	if len(values) == 0 {
		return nil
	}
	result := make(badoption.HTTPHeader, len(values))
	for key, value := range values {
		result[key] = []string{value}
	}
	return result
}

func parseOptionalDuration(value string) (badoption.Duration, error) {
	if value == "" {
		return 0, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, err
	}
	return badoption.Duration(duration), nil
}

func speedMbps(value string) int {
	return int(clash_utils.StringToBps(value) / 125000)
}

const (
	snellECHTLSALPN         = "snell-ech/1"
	snellECHTLSPreviousALPN = "oix-snell/1"
)

type snellObfsOptions struct {
	Mode              string `obfs:"mode,omitempty"`
	ALPN              string `obfs:"alpn,omitempty"`
	Protocol          string `obfs:"protocol,omitempty"`
	IdentityVersion   int    `obfs:"identity-version,omitempty"`
	LegacyFallback    bool   `obfs:"legacy-fallback,omitempty"`
	Preconnect        int    `obfs:"preconnect,omitempty"`
	Host              string `obfs:"host,omitempty"`
	SNI               string `obfs:"sni,omitempty"`
	ECHConfig         string `obfs:"ech-config,omitempty"`
	Insecure          bool   `obfs:"insecure,omitempty"`
	Fingerprint       string `obfs:"fingerprint,omitempty"`
	ClientFingerprint string `obfs:"client-fingerprint,omitempty"`
	SkipCertVerify    bool   `obfs:"skip-cert-verify,omitempty"`
}

func applySnellObfs(target *option.SnellOutboundOptions, source *clash_outbound.SnellOption) error {
	var sourceOptions snellObfsOptions
	decoder := structure.NewDecoder(structure.Option{TagName: "obfs", WeaklyTypedInput: true})
	if err := decoder.Decode(source.ObfsOpts, &sourceOptions); err != nil {
		return E.Cause(err, "decode Snell obfs options")
	}
	if sourceOptions.Fingerprint != "" {
		return validateClashCertificateFingerprint(sourceOptions.Fingerprint)
	}
	if sourceOptions.Mode == "" {
		return nil
	}
	if sourceOptions.Mode != "ech-tls" {
		target.ObfsOptions.ObfsMode = sourceOptions.Mode
		target.ObfsOptions.ObfsHost = sourceOptions.Host
		return nil
	}
	if source.Version != 4 {
		return E.New("Snell ECH-TLS requires version 4")
	}
	if sourceOptions.Insecure || sourceOptions.SkipCertVerify {
		return E.New("Snell ", snellECHTLSALPN, " requires certificate verification")
	}
	alpn, err := resolveSnellECHTLSALPN(sourceOptions.ALPN, sourceOptions.Protocol)
	if err != nil {
		return err
	}
	identityVersion := sourceOptions.IdentityVersion
	if identityVersion == 0 {
		identityVersion = 2
	}
	if identityVersion != 1 && identityVersion != 2 {
		return E.New("unsupported Snell ECH-TLS identity version: ", identityVersion)
	}
	if sourceOptions.LegacyFallback {
		identityVersion = 2
	}
	if sourceOptions.Preconnect < 0 || sourceOptions.Preconnect > 4 {
		return E.New("Snell ECH-TLS preconnect must be between 0 and 4")
	}
	if sourceOptions.Preconnect > 0 && !target.Reuse {
		return E.New("Snell ECH-TLS preconnect requires reuse")
	}
	serverName := sourceOptions.SNI
	if serverName == "" {
		serverName = sourceOptions.Host
	}
	if serverName == "" {
		serverName = source.Server
	}
	echConfig := sourceOptions.ECHConfig
	if echConfig == "" {
		return E.New("Snell ECH-TLS requires ech-config")
	}
	configBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(echConfig))
	if err != nil {
		return E.Cause(err, "decode Snell ECH config")
	}
	fingerprint := sourceOptions.ClientFingerprint
	if fingerprint == "" {
		fingerprint = source.ClientFingerprint
	}
	if fingerprint == "" {
		fingerprint = "chrome"
	}
	target.TLS = &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		ALPN:       []string{alpn},
		ECH:        &option.OutboundECHOptions{Enabled: true, Config: encodeECHConfig(configBytes)},
		UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: fingerprint},
	}
	target.Identity = identityVersion
	target.Preconnect = sourceOptions.Preconnect
	return nil
}

func resolveSnellECHTLSALPN(alpn string, protocol string) (string, error) {
	if protocol == snellECHTLSPreviousALPN {
		protocol = snellECHTLSALPN
	}
	if alpn != "" && protocol != "" && alpn != protocol {
		return "", E.New("Snell ECH-TLS alpn and protocol values conflict")
	}
	if alpn == "" {
		alpn = protocol
	}
	if alpn == "" {
		alpn = snellECHTLSALPN
	}
	if alpn != snellECHTLSALPN {
		return "", E.New("unsupported Snell ECH-TLS ALPN: ", alpn)
	}
	return alpn, nil
}

func clashWireGuardEndpoint(source *clash_outbound.WireGuardOption) (option.Endpoint, error) {
	if source.Name == "" || source.PrivateKey == "" {
		return option.Endpoint{}, E.New("WireGuard requires name and private-key")
	}
	if source.AmneziaWGOption != nil {
		return option.Endpoint{}, E.New("AmneziaWG options are not supported by target sing-box")
	}
	if err := validateWireGuardKey(source.PrivateKey, "private-key"); err != nil {
		return option.Endpoint{}, err
	}
	addresses, err := parseWireGuardAddresses(source.Ip, source.Ipv6)
	if err != nil {
		return option.Endpoint{}, err
	}
	if len(addresses) == 0 {
		return option.Endpoint{}, E.New("WireGuard requires ip or ipv6")
	}
	peers := source.Peers
	if len(peers) == 0 {
		peers = []clash_outbound.WireGuardPeerOption{source.WireGuardPeerOption}
	}
	targetPeers := make([]option.WireGuardPeer, 0, len(peers))
	for _, peer := range peers {
		if peer.Server == "" || peer.Port <= 0 || peer.Port > 65535 || peer.PublicKey == "" {
			return option.Endpoint{}, E.New("WireGuard peer requires server, port, and public-key")
		}
		if err := validateWireGuardKey(peer.PublicKey, "public-key"); err != nil {
			return option.Endpoint{}, err
		}
		if peer.PreSharedKey != "" {
			if err := validateWireGuardKey(peer.PreSharedKey, "pre-shared-key"); err != nil {
				return option.Endpoint{}, err
			}
		}
		allowedIPs, err := parsePrefixes(peer.AllowedIPs)
		if err != nil {
			return option.Endpoint{}, err
		}
		if len(allowedIPs) == 0 {
			for _, address := range addresses {
				if address.Addr().Is4() {
					allowedIPs = append(allowedIPs, netip.MustParsePrefix("0.0.0.0/0"))
				} else {
					allowedIPs = append(allowedIPs, netip.MustParsePrefix("::/0"))
				}
			}
		}
		targetPeers = append(targetPeers, option.WireGuardPeer{
			Address: peer.Server, Port: uint16(peer.Port), PublicKey: peer.PublicKey, PreSharedKey: peer.PreSharedKey,
			AllowedIPs: allowedIPs, PersistentKeepaliveInterval: uint16(source.PersistentKeepalive), Reserved: peer.Reserved,
		})
	}
	return option.Endpoint{Type: C.TypeWireGuard, Tag: source.Name, Options: &option.WireGuardEndpointOptions{
		Name: source.Name, MTU: uint32(source.MTU), Address: addresses, PrivateKey: source.PrivateKey, Peers: targetPeers, Workers: source.Workers,
		DialerOptions: clashDialerOptions(source.BasicOption),
	}}, nil
}

func validateWireGuardKey(value string, name string) error {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return E.New("invalid WireGuard ", name)
	}
	return nil
}

func parseWireGuardAddresses(ipv4 string, ipv6 string) ([]netip.Prefix, error) {
	var values []string
	if ipv4 != "" {
		if !strings.Contains(ipv4, "/") {
			ipv4 += "/32"
		}
		values = append(values, ipv4)
	}
	if ipv6 != "" {
		if !strings.Contains(ipv6, "/") {
			ipv6 += "/128"
		}
		values = append(values, ipv6)
	}
	return parsePrefixes(values)
}

func parsePrefixes(values []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, E.Cause(err, "parse prefix ", value)
		}
		result = append(result, prefix)
	}
	return result, nil
}

func clashOpenVPNEndpoint(source *clash_outbound.OpenVPNOption) (option.Endpoint, error) {
	if source.Name == "" || source.Server == "" || source.Port <= 0 || source.Port > 65535 {
		return option.Endpoint{}, E.New("OpenVPN requires name, server, and port")
	}
	if source.CA == "" || source.TLSCrypt == "" {
		return option.Endpoint{}, E.New("OpenVPN requires ca and tls-crypt")
	}
	if (source.Username == "" || source.Password == "") && (source.Cert == "" || source.Key == "") {
		return option.Endpoint{}, E.New("OpenVPN requires username/password or cert/key authentication")
	}
	tlsOptions := &option.OpenVPNOutboundTLSOptions{
		Certificate: optionalList(source.CA), ClientCertificate: optionalList(source.Cert), ClientKey: optionalList(source.Key),
	}
	if source.TLSCrypt != "" {
		tlsOptions.ControlWrap = &option.OpenVPNControlWrapOptions{Type: "tls-crypt", Key: optionalList(source.TLSCrypt)}
	}
	return option.Endpoint{Type: C.TypeOpenVPNClient, Tag: source.Name, Options: &option.OpenVPNClientEndpointOptions{
		DialerOptions: clashDialerOptions(source.BasicOption), ServerOptions: option.ServerOptions{Server: source.Server, ServerPort: uint16(source.Port)},
		OpenVPNEndpointOptions: option.OpenVPNEndpointOptions{Name: source.Name, MTU: uint32(source.MTU)}, Network: source.Proto,
		// The target fork currently serializes zero-valued badoption.Addr fields
		// as "invalid IP" even with omitempty. Valid unspecified addresses retain
		// pull-mode semantics and keep rendered/cache JSON round-trippable.
		PeerAddress: badoption.Addr(netip.IPv4Unspecified()), PeerAddressIPv6: badoption.Addr(netip.IPv6Unspecified()),
		Username: source.Username, Password: source.Password, TLS: tlsOptions, Cipher: source.Cipher, Auth: source.Auth,
		CompressionLZO: source.CompLZO,
		PingInterval:   badoption.Duration(time.Duration(source.Ping) * time.Second), PingRestart: badoption.Duration(time.Duration(source.PingRestart) * time.Second),
	}}, nil
}

func clashTailscaleEndpoint(source *clash_outbound.TailscaleOption) (option.Endpoint, error) {
	if source.Name == "" {
		return option.Endpoint{}, E.New("Tailscale requires name")
	}
	acceptRoutes := source.AcceptRoutes != nil && *source.AcceptRoutes
	exitNodeAllowLANAccess := source.ExitNodeAllowLANAccess != nil && *source.ExitNodeAllowLANAccess
	return option.Endpoint{Type: C.TypeTailscale, Tag: source.Name, Options: &option.TailscaleEndpointOptions{
		DialerOptions: clashDialerOptions(source.BasicOption), StateDirectory: source.StateDir, AuthKey: source.AuthKey, ControlURL: source.ControlURL,
		Ephemeral: source.Ephemeral, Hostname: source.Hostname, AcceptRoutes: acceptRoutes, ExitNode: source.ExitNode, ExitNodeAllowLANAccess: exitNodeAllowLANAccess,
	}}, nil
}

func clashShadowsocksCipher(cipher string) string {
	switch cipher {
	case "dummy":
		return "none"
	}
	return cipher
}

func clashNetworks(udpEnabled bool) option.NetworkList {
	if !udpEnabled {
		return N.NetworkTCP
	}
	return ""
}

func clashPluginName(plugin string) string {
	switch plugin {
	case "obfs":
		return "obfs-local"
	}
	return plugin
}

type shadowsocksPluginOptionsBuilder map[string]any

func (o shadowsocksPluginOptionsBuilder) Build() string {
	var opts []string
	for key, value := range o {
		if value == nil {
			continue
		}
		opts = append(opts, format.ToString(key, "=", value))
	}
	return strings.Join(opts, ";")
}

func clashPluginOptions(plugin string, opts map[string]any) string {
	options := make(shadowsocksPluginOptionsBuilder)
	switch plugin {
	case "obfs":
		options["obfs"] = opts["mode"]
		options["obfs-host"] = opts["host"]
	case "v2ray-plugin":
		options["mode"] = opts["mode"]
		options["tls"] = opts["tls"]
		options["host"] = opts["host"]
		options["path"] = opts["path"]
	}
	return options.Build()
}

func clashTransport(network string, httpOpts clash_outbound.HTTPOptions, h2Opts clash_outbound.HTTP2Options, grpcOpts clash_outbound.GrpcOptions, wsOpts clash_outbound.WSOptions) *option.V2RayTransportOptions {
	switch network {
	case "http":
		var headers map[string]badoption.Listable[string]
		for key, values := range httpOpts.Headers {
			if headers == nil {
				headers = make(map[string]badoption.Listable[string])
			}
			headers[key] = values
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Method:  httpOpts.Method,
				Path:    clashStringList(httpOpts.Path),
				Headers: headers,
			},
		}
	case "h2":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Path: h2Opts.Path,
				Host: h2Opts.Host,
			},
		}
	case "grpc":
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: grpcOpts.GrpcServiceName,
			},
		}
	case "ws":
		var headers map[string]badoption.Listable[string]
		for key, value := range wsOpts.Headers {
			if headers == nil {
				headers = make(map[string]badoption.Listable[string])
			}
			headers[key] = []string{value}
		}
		if wsOpts.V2rayHttpUpgrade {
			var host string
			if hostValues := headers["Host"]; len(hostValues) > 0 {
				host = hostValues[0]
			}
			return &option.V2RayTransportOptions{
				Type:               C.V2RayTransportTypeHTTPUpgrade,
				HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{Host: host, Path: wsOpts.Path, Headers: headers},
			}
		}
		return &option.V2RayTransportOptions{
			Type: C.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path:                wsOpts.Path,
				Headers:             headers,
				MaxEarlyData:        uint32(wsOpts.MaxEarlyData),
				EarlyDataHeaderName: wsOpts.EarlyDataHeaderName,
			},
		}
	default:
		return nil
	}
}

func clashStringList(list []string) string {
	if len(list) > 0 {
		return list[0]
	}
	return ""
}
