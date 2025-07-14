package proxy

import (
	"encoding/json"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/ghodss/yaml"
)

func ExplodeClash(clash string) (ProxyList, error) {
	proxyList := make(ProxyList, 0)
	yamlnode := make(map[string]interface{})
	jsond, err := yaml.YAMLToJSON([]byte(clash))
	if err != nil {
		return nil, err
	}
	json.Unmarshal(jsond, &yamlnode)

	section := "Proxy"
	if _, ok := yamlnode["proxies"]; ok {
		section = "proxies"
	}

	for _, v := range yamlnode[section].([]interface{}) {
		var proxyType, remark, server string // common
		var port int                         // common
		var udp, scv bool                    // common
		var singleProxy map[string]interface{}

		singleProxy = v.(map[string]interface{})
		tool.Base64DecodeByte(clash)
		proxyType = tool.SafeAsString(singleProxy, "type")
		remark = tool.SafeAsString(singleProxy, "name")
		server = tool.SafeAsString(singleProxy, "server")
		port = tool.SafeAsInt(singleProxy, "port")
		if port == 0 {
			continue
		}
		udp = tool.SafeAsBool(singleProxy, "udp")
		scv = tool.SafeAsBool(singleProxy, "skip-cert-verify")

		var proxy Proxy
		switch proxyType {
		case "socks5":
			socks5Proxy := &Socks5Proxy{}
			socks5Proxy.Group = "socks_group"
			socks5Proxy.Name = remark
			socks5Proxy.Server = server
			socks5Proxy.Port = port
			socks5Proxy.Username = tool.SafeAsString(singleProxy, "username")
			socks5Proxy.Password = tool.SafeAsString(singleProxy, "password")
			socks5Proxy.TLSSecure = tool.SafeAsBool(singleProxy, "tls")
			socks5Proxy.Fingerprint = tool.SafeAsString(singleProxy, "fingerprint")
			socks5Proxy.SkipCertVerify = scv
			socks5Proxy.UDP = udp
			socks5Proxy.IpVersion = tool.SafeAsString(singleProxy, "ip-version")

			proxy = socks5Proxy

		case "http":
			httpProxy := &HTTPProxy{}
			httpProxy.Group = "http_group"
			httpProxy.Name = remark
			httpProxy.Server = server
			httpProxy.Port = port
			httpProxy.Username = tool.SafeAsString(singleProxy, "username")
			httpProxy.Password = tool.SafeAsString(singleProxy, "password")
			httpProxy.TLSSecure = tool.SafeAsBool(singleProxy, "tls")

			proxy = httpProxy

		case "ss":
			ssProxy := &SSProxy{}
			ssProxy.Group = "ss_group"
			ssProxy.Name = remark
			ssProxy.Server = server
			ssProxy.Port = tool.SafeAsInt(singleProxy, "port")
			ssProxy.Password = tool.SafeAsString(singleProxy, "password")
			ssProxy.UDP = udp
			ssProxy.UdpOverTCP = tool.SafeAsBool(singleProxy, "udp-over-tcp")
			ssProxy.UdpOverTCPVersion = tool.SafeAsInt(singleProxy, "udp-over-tcp-version")
			ssProxy.IpVersion = tool.SafeAsString(singleProxy, "ip-version")
			ssProxy.Smux.Enable = tool.SafeAsBool(singleProxy, "smux", "enabled")

			cipher := tool.SafeAsString(singleProxy, "cipher")
			// support for go-shadowsocks2
			if cipher == "AEAD_CHACHA20_POLY1305" {
				cipher = "chacha20-ietf-poly1305"
			} else if strings.Contains(cipher, "AEAD") {
				cipher = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(cipher, "AEAD_", ""), "_", "-"))
			}
			ssProxy.EncryptMethod = cipher

			if singleProxy["plugin"] != nil {
				plugin := tool.SafeAsString(singleProxy, "plugin")
				switch plugin {
				case "obfs":
					ssProxy.Plugin.Name = "obfs-local"
					ssProxy.Plugin.Raw = "obfs-local"
					ssProxy.Plugin.Params = tool.SafeAsMap(singleProxy, "plugin-opts")
					for k, v := range ssProxy.Plugin.Params {
						switch v := v.(type) {
						case bool:
							if v {
								ssProxy.Plugin.Raw += ";" + k
							}
						default:
							// 如果不是字符串类型，尝试将其转换为字符串
							ssProxy.Plugin.Raw += ";" + k + "=" + tool.SafeAsString(ssProxy.Plugin.Params, k)
						}
					}
				case "v2ray-plugin", "gost-plugin", "shadow-tls", "restls":
					ssProxy.Plugin.Name = plugin
					ssProxy.Plugin.Raw = plugin
					ssProxy.Plugin.Params = tool.SafeAsMap(singleProxy, "plugin-opts")
					for k, _ := range ssProxy.Plugin.Params {
						switch v := v.(type) {
						case bool:
							if v {
								ssProxy.Plugin.Raw += ";" + k
							}
						default:
							// 如果不是字符串类型，尝试将其转换为字符串
							ssProxy.Plugin.Raw += ";" + k + "=" + tool.SafeAsString(ssProxy.Plugin.Params, k)
						}
					}
				}
			} else if singleProxy["obfs"] != nil {
				ssProxy.Plugin.Name = "obfs-local"
				ssProxy.Plugin.Raw = "obfs-local"
				ssProxy.Plugin.Params = tool.SafeAsMap(singleProxy, "obfs-opts")
				for k, v := range ssProxy.Plugin.Params {
					switch v := v.(type) {
					case bool:
						if v {
							ssProxy.Plugin.Raw += ";" + k
						}
					default:
						// 如果不是字符串类型，尝试将其转换为字符串
						ssProxy.Plugin.Raw += ";" + k + "=" + tool.SafeAsString(ssProxy.Plugin.Params, k)
					}
				}
			}

			proxy = ssProxy

		case "ssr":
			ssrProxy := &SSRProxy{}
			ssrProxy.Group = "ssr_group"
			ssrProxy.Name = remark
			ssrProxy.Server = server
			ssrProxy.Port = port
			ssrProxy.UDP = udp
			ssrProxy.Password = tool.SafeAsString(singleProxy, "password")
			ssrProxy.Protocol = tool.SafeAsString(singleProxy, "protocol")
			ssrProxy.OBFS = tool.SafeAsString(singleProxy, "obfs")

			cipher := tool.SafeAsString(singleProxy, "cipher")
			if cipher == "dummy" {
				cipher = "none"
			}
			ssrProxy.EncryptMethod = cipher

			var protoparam, obfsparam string
			if singleProxy["protocol-param"] != nil {
				protoparam = tool.SafeAsString(singleProxy, "protocol-param")
			} else {
				protoparam = tool.SafeAsString(singleProxy, "protocolparam")
			}
			if singleProxy["obfs-param"] != nil {
				obfsparam = tool.SafeAsString(singleProxy, "obfs-param")
			} else {
				obfsparam = tool.SafeAsString(singleProxy, "obfsparam")
			}
			ssrProxy.ProtocolParam = protoparam
			ssrProxy.OBFSParam = obfsparam

			proxy = ssrProxy

		case "trojan":
			trojanProxy := &TrojanProxy{}
			trojanProxy.Group = "trojan_group"
			trojanProxy.Name = remark
			trojanProxy.Server = server
			trojanProxy.Port = port
			trojanProxy.Password = tool.SafeAsString(singleProxy, "password")
			trojanProxy.UDP = udp

			trojanProxy.SNI = tool.SafeAsString(singleProxy, "sni")
			trojanProxy.ALPN = tool.SafeAsStringArray(singleProxy, "alpn")
			trojanProxy.ClientFingerprint = tool.SafeAsString(singleProxy, "client-fingerprint")
			trojanProxy.Fingerprint = tool.SafeAsString(singleProxy, "fingerprint")
			trojanProxy.SkipCertVerify = scv
			trojanProxy.Smux.Enable = tool.SafeAsBool(singleProxy, "smux", "enabled")

			if singleProxy["ss-opts"] != nil {
				trojanProxy.SSOpts.Enabled = tool.SafeAsBool(singleProxy, "ss-opts", "enabled")
				trojanProxy.SSOpts.Method = tool.SafeAsString(singleProxy, "ss-opts", "method")
				trojanProxy.SSOpts.Password = tool.SafeAsString(singleProxy, "ss-opts", "password")
			}
			if singleProxy["reality-opts"] != nil {
				trojanProxy.RealityOpts.PublicKey = tool.SafeAsString(singleProxy, "reality-opts", "public-key")
				trojanProxy.RealityOpts.ShortID = tool.SafeAsString(singleProxy, "reality-opts", "short-id")
			}

			net := tool.SafeAsString(singleProxy, "network")
			switch net {
			case "grpc":
				trojanProxy.GRPCOpts.ServiceName = tool.SafeAsString(singleProxy, "grpc-opts", "grpc-service-name")
			case "ws":
				trojanProxy.WSOpts.Path = tool.SafeAsString(singleProxy, "ws-opts", "path")
				trojanProxy.WSOpts.Headers = tool.SafeAsMap(singleProxy, "ws-opts", "headers")
				trojanProxy.WSOpts.MaxEarlyData = tool.SafeAsInt(singleProxy, "ws-opts", "max-early-data")
				trojanProxy.WSOpts.EarlyDataHeaderName = tool.SafeAsString(singleProxy, "ws-opts", "earlyDataHeaderName")
				trojanProxy.WSOpts.V2rayHttpUpgrade = tool.SafeAsBool(singleProxy, "ws-opts", "v2rayHttpUpgrade")
				trojanProxy.WSOpts.V2rayHttpUpgradeFastOpen = tool.SafeAsBool(singleProxy, "ws-opts", "v2rayHttpUpgradeFastOpen")
			default:
				net = "tcp"
			}
			trojanProxy.Network = net

			proxy = trojanProxy

		case "vmess":
			vmessProxy := &Vmess{}
			vmessProxy.Group = "vmess_group"
			vmessProxy.Name = remark
			vmessProxy.Server = server
			vmessProxy.Port = port
			vmessProxy.SkipCertVerify = scv
			vmessProxy.UDP = udp

			vmessProxy.UUID = tool.SafeAsString(singleProxy, "uuid")
			vmessProxy.AlterID = tool.SafeAsInt(singleProxy, "alterId")
			vmessProxy.Cipher = tool.SafeAsString(singleProxy, "cipher")
			vmessProxy.PacketEncoding = tool.SafeAsString(singleProxy, "packet-encoding")
			vmessProxy.GlobalPadding = tool.SafeAsBool(singleProxy, "global-padding")
			vmessProxy.AuthenticatedLength = tool.SafeAsBool(singleProxy, "authenticated-length")

			vmessProxy.TLSSecure = tool.SafeAsBool(singleProxy, "tls")
			vmessProxy.ServerName = tool.SafeAsString(singleProxy, "servername")
			vmessProxy.ALPN = tool.SafeAsStringArray(singleProxy, "alpn")
			vmessProxy.Fingerprint = tool.SafeAsString(singleProxy, "fingerprint")
			vmessProxy.ClientFingerprint = tool.SafeAsString(singleProxy, "client-fingerprint")
			vmessProxy.Smux.Enable = tool.SafeAsBool(singleProxy, "smux", "enabled")

			if singleProxy["reality-opts"] != nil {
				vmessProxy.RealityOpts.PublicKey = tool.SafeAsString(singleProxy, "reality-opts", "public-key")
				vmessProxy.RealityOpts.ShortID = tool.SafeAsString(singleProxy, "reality-opts", "short-id")
			}

			net := tool.SafeAsString(singleProxy, "network")
			if net == "" {
				net = "tcp"
			}
			var path, host string
			switch net {
			case "http":
				vmessProxy.HttpOpts.Method = tool.SafeAsString(singleProxy, "http-opts", "method")
				vmessProxy.HttpOpts.Path = tool.SafeAsStringArray(singleProxy, "http-opts", "path")
				vmessProxy.HttpOpts.Headers = tool.SafeAsMap(singleProxy, "http-opts", "headers")

				path = tool.SafeAsString(singleProxy, "http-opts", "path", "0")
				host = tool.SafeAsString(vmessProxy.HttpOpts.Headers, "Host")
			case "h2":
				vmessProxy.H2Opts.Host = tool.SafeAsStringArray(singleProxy, "h2-opts", "host")
				vmessProxy.H2Opts.Path = tool.SafeAsString(singleProxy, "h2-opts", "path")

				path = vmessProxy.H2Opts.Path
				host = vmessProxy.H2Opts.Host[0]
			case "grpc":
				vmessProxy.GRPCOpts.ServiceName = tool.SafeAsString(singleProxy, "grpc-opts", "grpc-service-name")
				path = vmessProxy.GRPCOpts.ServiceName
				host = vmessProxy.ServerName
			case "ws":
				if singleProxy["ws-opts"] != nil {
					vmessProxy.WSOpts.Path = tool.SafeAsString(singleProxy, "ws-opts", "path")
					vmessProxy.WSOpts.Headers = tool.SafeAsMap(singleProxy, "ws-opts", "headers")
					vmessProxy.WSOpts.MaxEarlyData = tool.SafeAsInt(singleProxy, "ws-opts", "max-early-data")
					vmessProxy.WSOpts.EarlyDataHeaderName = tool.SafeAsString(singleProxy, "ws-opts", "earlyDataHeaderName")
					vmessProxy.WSOpts.V2rayHttpUpgrade = tool.SafeAsBool(singleProxy, "ws-opts", "v2rayHttpUpgrade")
					vmessProxy.WSOpts.V2rayHttpUpgradeFastOpen = tool.SafeAsBool(singleProxy, "ws-opts", "v2rayHttpUpgradeFastOpen")

					path = vmessProxy.WSOpts.Path
					host = tool.SafeAsString(vmessProxy.WSOpts.Headers, "Host")
					if host == "" {
						host = tool.SafeAsString(vmessProxy.WSOpts.Headers, "HOST")
					}
				} else {
					vmessProxy.WSOpts.Path = tool.SafeAsString(singleProxy, "ws-path")
					vmessProxy.WSOpts.Headers = map[string]interface{}{
						"Host": tool.SafeAsString(singleProxy, "ws-headers", "Host"),
					}
					path = vmessProxy.WSOpts.Path
					host = vmessProxy.WSOpts.Headers["Host"].(string)
				}
			}
			vmessProxy.Network = net
			vmessProxy.Path = path
			vmessProxy.Host = host

			proxy = vmessProxy

		case "vless":
			vlessProxy := &VlessProxy{}
			vlessProxy.Group = "vless_group"
			vlessProxy.Name = remark
			vlessProxy.Server = server
			vlessProxy.Port = port
			vlessProxy.SkipCertVerify = scv
			vlessProxy.UDP = udp

			vlessProxy.UUID = tool.SafeAsString(singleProxy, "uuid")
			vlessProxy.SNI = tool.SafeAsString(singleProxy, "servername")
			vlessProxy.Flow = tool.SafeAsString(singleProxy, "flow")
			vlessProxy.Security = tool.SafeAsString(singleProxy, "security")
			vlessProxy.ALPN = tool.SafeAsStringArray(singleProxy, "alpn")
			vlessProxy.ClientFingerprint = tool.SafeAsString(singleProxy, "client-fingerprint")
			vlessProxy.Fingerprint = tool.SafeAsString(singleProxy, "fingerprint")
			vlessProxy.Smux.Enable = tool.SafeAsBool(singleProxy, "smux", "enabled")

			if vlessProxy.PacketEncoding = tool.SafeAsString(singleProxy, "packet-encoding"); vlessProxy.PacketEncoding == "xudp" {
				vlessProxy.XUDP = true
			}

			if singleProxy["reality-opts"] != nil {
				vlessProxy.Security = "reality"
				vlessProxy.RealityOpts.PublicKey = tool.SafeAsString(singleProxy, "reality-opts", "public-key")
				vlessProxy.RealityOpts.ShortID = tool.SafeAsString(singleProxy, "reality-opts", "short-id")
			}

			if vlessProxy.TLSSecure = tool.SafeAsBool(singleProxy, "tls"); vlessProxy.TLSSecure {
				vlessProxy.Security = "tls"
			}

			vlessProxy.Network = tool.SafeAsString(singleProxy, "network")
			if vlessProxy.Network == "" {
				vlessProxy.Network = "tcp"
			}
			switch vlessProxy.Network {
			case "http":
				vlessProxy.HttpOpts.Method = tool.SafeAsString(singleProxy, "http-opts", "method")
				vlessProxy.HttpOpts.Path = tool.SafeAsStringArray(singleProxy, "http-opts", "path")
				vlessProxy.HttpOpts.Headers = tool.SafeAsMap(singleProxy, "http-opts", "headers")
			case "h2":
				vlessProxy.H2Opts.Host = tool.SafeAsStringArray(singleProxy, "h2-opts", "host")
				vlessProxy.H2Opts.Path = tool.SafeAsString(singleProxy, "h2-opts", "path")
			case "ws":
				vlessProxy.WSOpts.Path = tool.SafeAsString(singleProxy, "ws-opts", "path")
				vlessProxy.WSOpts.Headers = tool.SafeAsMap(singleProxy, "ws-opts", "headers")
			case "grpc":
				vlessProxy.GRPCOpts.ServiceName = tool.SafeAsString(singleProxy, "grpc-opts", "grpc-service-name")
			}

			proxy = vlessProxy

		case "hysteria":
			hysteriaProxy := &HysteriaProxy{}
			hysteriaProxy.Group = "hysteria_group"
			hysteriaProxy.Name = remark
			hysteriaProxy.Server = server
			hysteriaProxy.Port = port
			hysteriaProxy.Ports = tool.SafeAsString(singleProxy, "ports")

			// 优先获取 auth_str，若为空则获取 auth-str
			auth := tool.SafeAsString(singleProxy, "auth-str")
			if auth == "" {
				auth = tool.SafeAsString(singleProxy, "auth_str")
			}
			hysteriaProxy.Auth = auth

			hysteriaProxy.Obfs = tool.SafeAsString(singleProxy, "obfs")
			hysteriaProxy.ALPN = tool.SafeAsStringArray(singleProxy, "alpn")
			hysteriaProxy.Protocol = tool.SafeAsString(singleProxy, "protocol")
			hysteriaProxy.Up = tool.SafeAsString(singleProxy, "up")
			hysteriaProxy.Down = tool.SafeAsString(singleProxy, "down")
			hysteriaProxy.SNI = tool.SafeAsString(singleProxy, "sni")
			hysteriaProxy.SkipCertVerify = scv
			hysteriaProxy.RecvWindowConn = tool.SafeAsInt(singleProxy, "recv-window-conn")
			hysteriaProxy.RecvWindow = tool.SafeAsInt(singleProxy, "recv-window")
			hysteriaProxy.Ca = tool.SafeAsString(singleProxy, "ca")
			hysteriaProxy.CaStr = tool.SafeAsString(singleProxy, "ca-str")
			hysteriaProxy.DisableMTU = tool.SafeAsBool(singleProxy, "disable_mtu_discovery")
			hysteriaProxy.Fingerprint = tool.SafeAsString(singleProxy, "fingerprint")
			hysteriaProxy.FastOpen = tool.SafeAsBool(singleProxy, "fast-open")

			proxy = hysteriaProxy

		case "hysteria2":
			hy2Proxy := &Hy2Proxy{}
			hy2Proxy.Group = "hy2_group"
			hy2Proxy.Name = remark
			hy2Proxy.Server = server
			hy2Proxy.Port = port
			hy2Proxy.Auth = tool.SafeAsString(singleProxy, "password")
			hy2Proxy.Up = tool.SafeAsString(singleProxy, "up")
			hy2Proxy.Down = tool.SafeAsString(singleProxy, "down")
			hy2Proxy.Obfs = tool.SafeAsString(singleProxy, "obfs")
			hy2Proxy.ObfsPassword = tool.SafeAsString(singleProxy, "obfs-password")
			hy2Proxy.SNI = tool.SafeAsString(singleProxy, "sni")
			hy2Proxy.SkipCertVerify = scv
			hy2Proxy.Fingerprint = tool.SafeAsString(singleProxy, "fingerprint")
			hy2Proxy.ALPN = tool.SafeAsStringArray(singleProxy, "alpn")
			hy2Proxy.Ca = tool.SafeAsString(singleProxy, "ca")
			hy2Proxy.CaStr = tool.SafeAsString(singleProxy, "ca-str")

			proxy = hy2Proxy

		case "snell":
			obfs := tool.SafeAsString(singleProxy, "obfs")
			obfsParam := tool.SafeAsString(singleProxy, "obfs-param")

			snellProxy := &SnellProxy{}
			snellProxy.Group = "snell_group"
			snellProxy.Name = remark
			snellProxy.Server = server
			snellProxy.Port = tool.SafeAsInt(singleProxy, "port")
			snellProxy.PSK = tool.SafeAsString(singleProxy, "psk")
			snellProxy.Version = tool.SafeAsInt(singleProxy, "version")
			snellProxy.Obfs = obfs
			snellProxy.ObfsParam = obfsParam
			snellProxy.UDP = udp
			snellProxy.SkipCertVerify = scv
			proxy = snellProxy
		}

		if proxy != nil {
			proxyList = append(proxyList, proxy)
		}
	}
	return proxyList, nil
}

func ProxieToClash(node Proxy) map[string]any {
	clashNode := make(map[string]interface{})
	clashNode["name"] = node.GetName()
	clashNode["type"] = node.GetType()

	// TODO: 判断空值是否输出
	// https://github.com/tindy2013/subconverter/blob/master/src/generator/config/subexport.cpp#L227
	switch node.GetType() {
	case "socks5":
		socks5Node := node.(*Socks5Proxy)
		clashNode["server"] = socks5Node.Server
		clashNode["port"] = socks5Node.Port
		clashNode["username"] = socks5Node.Username
		clashNode["password"] = socks5Node.Password
		clashNode["tls"] = socks5Node.TLSSecure
		if socks5Node.Fingerprint != "" {
			clashNode["fingerprint"] = socks5Node.Fingerprint
		}
		clashNode["skip-cert-verify"] = socks5Node.SkipCertVerify
		clashNode["udp"] = socks5Node.UDP
		if socks5Node.IpVersion != "" {
			clashNode["ip-version"] = socks5Node.IpVersion
		}
	case "http", "https":
		httpNode := node.(*HTTPProxy)
		clashNode["server"] = httpNode.Server
		clashNode["port"] = httpNode.Port
		clashNode["username"] = httpNode.Username
		clashNode["password"] = httpNode.Password
		clashNode["tls"] = httpNode.TLSSecure
		clashNode["skip-cert-verify"] = httpNode.SkipCertVerify
		if httpNode.SNI != "" {
			clashNode["sni"] = httpNode.SNI
		}
		if httpNode.Fingerprint != "" {
			clashNode["fingerprint"] = httpNode.Fingerprint
		}
		if httpNode.IpVersion != "" {
			clashNode["ip-version"] = httpNode.IpVersion
		}
		clashNode["headers"] = httpNode.Headers
	case "ss":
		// TODO: 判断协议是否符合
		ssNode := node.(*SSProxy)
		clashNode["server"] = ssNode.Server
		clashNode["port"] = ssNode.Port
		clashNode["cipher"] = ssNode.EncryptMethod
		clashNode["password"] = ssNode.Password
		clashNode["udp"] = ssNode.UDP
		if ssNode.UDP {
			clashNode["udp-over-tcp"] = ssNode.UdpOverTCP
		}
		if ssNode.UdpOverTCPVersion != 0 {
			clashNode["udp-over-tcp-version"] = ssNode.UdpOverTCPVersion
		}
		if ssNode.IpVersion != "" {
			clashNode["ip-version"] = ssNode.IpVersion
		}

		switch ssNode.Plugin.Name {
		case "simple-obfs", "obfs-local":
			clashNode["plugin"] = "obfs"
			pluginOpts := make(map[string]interface{})
			for k, v := range ssNode.Plugin.Params {
				pluginOpts[k] = v
			}
			clashNode["plugin-opts"] = pluginOpts
		default:
			clashNode["plugin"] = ssNode.Plugin.Name
			pluginOpts := make(map[string]interface{})
			for k, v := range ssNode.Plugin.Params {
				pluginOpts[k] = v
			}
			clashNode["plugin-opts"] = pluginOpts
		}

		if ssNode.Smux.Enable {
			clashNode["smux"] = map[string]interface{}{
				"enabled": ssNode.Smux.Enable,
			}
		}
	case "ssr":
		ssrNode := node.(*SSRProxy)
		clashNode["server"] = ssrNode.Server
		clashNode["port"] = ssrNode.Port
		// TODO: 判断协议是否符合
		if ssrNode.EncryptMethod == "none" {
			clashNode["cipher"] = "dummy"
		} else {
			clashNode["cipher"] = ssrNode.EncryptMethod
		}
		clashNode["password"] = ssrNode.Password
		clashNode["obfs"] = ssrNode.OBFS
		clashNode["protocol"] = ssrNode.Protocol
		clashNode["obfs-param"] = ssrNode.OBFSParam
		clashNode["protocol-param"] = ssrNode.ProtocolParam
		clashNode["udp"] = ssrNode.UDP
	case "trojan":
		trojanNode := node.(*TrojanProxy)
		clashNode["server"] = trojanNode.Server
		clashNode["port"] = trojanNode.Port
		clashNode["password"] = trojanNode.Password
		clashNode["udp"] = trojanNode.UDP
		clashNode["sni"] = trojanNode.SNI
		if len(trojanNode.ALPN) > 0 {
			clashNode["alpn"] = trojanNode.ALPN
		}
		clashNode["client-fingerprint"] = trojanNode.ClientFingerprint
		clashNode["fingerprint"] = trojanNode.Fingerprint
		clashNode["skip-cert-verify"] = trojanNode.SkipCertVerify
		if trojanNode.SSOpts.Method != "" {
			r := map[string]interface{}{
				"enabled": trojanNode.SSOpts.Enabled,
				"method":  trojanNode.SSOpts.Method,
			}
			if trojanNode.SSOpts.Password != "" {
				r["password"] = trojanNode.SSOpts.Password
			}
			clashNode["ss-opts"] = r
		}
		if trojanNode.RealityOpts.PublicKey != "" {
			r := map[string]interface{}{
				"public-key": trojanNode.RealityOpts.PublicKey,
			}
			if trojanNode.RealityOpts.ShortID != "" {
				r["short-id"] = trojanNode.RealityOpts.ShortID
			}
			clashNode["reality-opts"] = r
		}
		if trojanNode.Smux.Enable {
			clashNode["smux"] = map[string]interface{}{
				"enabled": trojanNode.Smux.Enable,
			}
		}

		clashNode["network"] = trojanNode.Network
		switch trojanNode.Network {
		case "grpc":
			clashNode["grpc-opts"] = map[string]interface{}{"grpc-service-name": trojanNode.GRPCOpts.ServiceName}
		case "ws":
			ws := map[string]interface{}{
				"path":    trojanNode.WSOpts.Path,
				"headers": trojanNode.WSOpts.Headers,
			}
			if trojanNode.WSOpts.MaxEarlyData > 0 {
				ws["max-early-data"] = trojanNode.WSOpts.MaxEarlyData
			}
			if trojanNode.WSOpts.EarlyDataHeaderName != "" {
				ws["early-data-header-name"] = trojanNode.WSOpts.EarlyDataHeaderName
			}
			if trojanNode.WSOpts.V2rayHttpUpgrade {
				ws["v2rayHttpUpgrade"] = trojanNode.WSOpts.V2rayHttpUpgrade
			}
			if trojanNode.WSOpts.V2rayHttpUpgradeFastOpen {
				ws["v2rayHttpUpgradeFastOpen"] = trojanNode.WSOpts.V2rayHttpUpgradeFastOpen
			}

			clashNode["ws-opts"] = ws
		}
	case "vmess":
		vmessNode := node.(*Vmess)
		clashNode["server"] = vmessNode.Server
		clashNode["port"] = vmessNode.Port
		clashNode["udp"] = vmessNode.UDP
		clashNode["uuid"] = vmessNode.UUID
		clashNode["alterId"] = vmessNode.AlterID
		clashNode["cipher"] = vmessNode.Cipher
		if vmessNode.PacketEncoding != "" {
			clashNode["packet-encoding"] = vmessNode.PacketEncoding
		}
		clashNode["global-padding"] = vmessNode.GlobalPadding
		clashNode["authenticated-length"] = vmessNode.AuthenticatedLength

		clashNode["tls"] = vmessNode.TLSSecure
		clashNode["servername"] = vmessNode.ServerName
		if len(vmessNode.ALPN) > 0 {
			clashNode["alpn"] = vmessNode.ALPN
		}
		clashNode["fingerprint"] = vmessNode.Fingerprint
		clashNode["client-fingerprint"] = vmessNode.ClientFingerprint
		clashNode["skip-cert-verify"] = vmessNode.SkipCertVerify

		if vmessNode.RealityOpts.PublicKey != "" {
			r := map[string]interface{}{
				"public-key": vmessNode.RealityOpts.PublicKey,
			}
			if vmessNode.RealityOpts.ShortID != "" {
				r["short-id"] = vmessNode.RealityOpts.ShortID
			}
			clashNode["reality-opts"] = r
		}

		if vmessNode.Smux.Enable {
			clashNode["smux"] = map[string]interface{}{
				"enabled": vmessNode.Smux.Enable,
			}
		}

		clashNode["network"] = vmessNode.Network
		switch vmessNode.Network {
		case "ws":
			ws := map[string]interface{}{
				"path":    vmessNode.WSOpts.Path,
				"headers": vmessNode.WSOpts.Headers,
			}
			if vmessNode.WSOpts.MaxEarlyData > 0 {
				ws["max-early-data"] = vmessNode.WSOpts.MaxEarlyData
			}
			if vmessNode.WSOpts.EarlyDataHeaderName != "" {
				ws["early-data-header-name"] = vmessNode.WSOpts.EarlyDataHeaderName
			}
			if vmessNode.WSOpts.V2rayHttpUpgrade {
				ws["v2rayHttpUpgrade"] = vmessNode.WSOpts.V2rayHttpUpgrade
			}
			if vmessNode.WSOpts.V2rayHttpUpgradeFastOpen {
				ws["v2rayHttpUpgradeFastOpen"] = vmessNode.WSOpts.V2rayHttpUpgradeFastOpen
			}

			clashNode["ws-opts"] = ws
		case "http":
			clashNode["http-opts"] = map[string]interface{}{
				"method":  vmessNode.HttpOpts.Method,
				"path":    vmessNode.HttpOpts.Path,
				"headers": vmessNode.HttpOpts.Headers,
			}
		case "h2":
			clashNode["h2-opts"] = map[string]interface{}{
				"path": vmessNode.H2Opts.Path,
				"host": vmessNode.H2Opts.Host,
			}
		case "grpc":
			clashNode["grpc-opts"] = map[string]interface{}{"grpc-service-name": vmessNode.Path}
		}
	case "vless":
		vlessNode := node.(*VlessProxy)
		clashNode["server"] = vlessNode.Server
		clashNode["port"] = vlessNode.Port
		clashNode["udp"] = vlessNode.UDP
		clashNode["uuid"] = vlessNode.UUID
		clashNode["flow"] = vlessNode.Flow
		clashNode["packet-encoding"] = vlessNode.PacketEncoding
		clashNode["tls"] = vlessNode.TLSSecure
		clashNode["servername"] = vlessNode.SNI
		if len(vlessNode.ALPN) > 0 {
			clashNode["alpn"] = vlessNode.ALPN
		}
		clashNode["fingerprint"] = vlessNode.Fingerprint
		clashNode["client-fingerprint"] = vlessNode.ClientFingerprint
		clashNode["skip-cert-verify"] = vlessNode.SkipCertVerify
		clashNode["network"] = vlessNode.Network
		clashNode["smux"] = map[string]interface{}{
			"enabled": vlessNode.Smux.Enable,
		}

		if vlessNode.RealityOpts.PublicKey != "" {
			r := map[string]interface{}{
				"public-key": vlessNode.RealityOpts.PublicKey,
			}
			if vlessNode.RealityOpts.ShortID != "" {
				r["short-id"] = vlessNode.RealityOpts.ShortID
			}
			clashNode["reality-opts"] = r
		}

		switch vlessNode.Network {
		case "http":
			clashNode["http-opts"] = map[string]interface{}{
				"method":  vlessNode.HttpOpts.Method,
				"path":    vlessNode.HttpOpts.Path,
				"headers": vlessNode.HttpOpts.Headers,
			}
		case "h2":
			clashNode["h2-opts"] = map[string]interface{}{
				"path": vlessNode.H2Opts.Path,
				"host": vlessNode.H2Opts.Host,
			}
		case "ws":
			ws := map[string]interface{}{
				"path":    vlessNode.WSOpts.Path,
				"headers": vlessNode.WSOpts.Headers,
			}
			if vlessNode.WSOpts.MaxEarlyData > 0 {
				ws["max-early-data"] = vlessNode.WSOpts.MaxEarlyData
			}
			if vlessNode.WSOpts.EarlyDataHeaderName != "" {
				ws["early-data-header-name"] = vlessNode.WSOpts.EarlyDataHeaderName
			}
			if vlessNode.WSOpts.V2rayHttpUpgrade {
				ws["v2rayHttpUpgrade"] = vlessNode.WSOpts.V2rayHttpUpgrade
			}
			if vlessNode.WSOpts.V2rayHttpUpgradeFastOpen {
				ws["v2rayHttpUpgradeFastOpen"] = vlessNode.WSOpts.V2rayHttpUpgradeFastOpen
			}

			clashNode["ws-opts"] = ws
		case "grpc":
			clashNode["grpc-opts"] = map[string]interface{}{
				"grpc-service-name": vlessNode.GRPCOpts.ServiceName,
			}
		}
	case "hysteria":
		hysteriaNode := node.(*HysteriaProxy)
		clashNode["server"] = hysteriaNode.Server
		clashNode["port"] = hysteriaNode.Port
		if hysteriaNode.Ports != "" {
			clashNode["ports"] = hysteriaNode.Ports
		}
		if hysteriaNode.Auth != "" {
			clashNode["auth-str"] = hysteriaNode.Auth
		}
		if hysteriaNode.Obfs != "" {
			clashNode["obfs"] = hysteriaNode.Obfs
		}
		if len(hysteriaNode.ALPN) > 0 {
			clashNode["alpn"] = hysteriaNode.ALPN
		}
		if hysteriaNode.Protocol != "" {
			clashNode["protocol"] = hysteriaNode.Protocol
		}
		clashNode["up"] = hysteriaNode.Up
		clashNode["down"] = hysteriaNode.Down
		if hysteriaNode.SNI != "" {
			clashNode["sni"] = hysteriaNode.SNI
		}
		if hysteriaNode.SkipCertVerify {
			clashNode["skip-cert-verify"] = hysteriaNode.SkipCertVerify
		}
		if hysteriaNode.RecvWindowConn > 0 {
			clashNode["recv-window-conn"] = hysteriaNode.RecvWindowConn
		}
		if hysteriaNode.RecvWindow > 0 {
			clashNode["recv-window"] = hysteriaNode.RecvWindow
		}
		if hysteriaNode.Ca != "" {
			clashNode["ca"] = hysteriaNode.Ca
		}
		if hysteriaNode.CaStr != "" {
			clashNode["ca-str"] = hysteriaNode.CaStr
		}
		if hysteriaNode.DisableMTU {
			clashNode["disable_mtu_discovery"] = hysteriaNode.DisableMTU
		}
		if hysteriaNode.Fingerprint != "" {
			clashNode["fingerprint"] = hysteriaNode.Fingerprint
		}
		if hysteriaNode.FastOpen {
			clashNode["fast-open"] = hysteriaNode.FastOpen
		}
	case "hysteria2":
		hy2Node := node.(*Hy2Proxy)
		clashNode["server"] = hy2Node.Server
		clashNode["port"] = hy2Node.Port
		clashNode["password"] = hy2Node.Auth
		clashNode["up"] = hy2Node.Up
		clashNode["down"] = hy2Node.Down
		clashNode["fingerprint"] = hy2Node.Fingerprint
		if hy2Node.Obfs != "" {
			clashNode["obfs"] = hy2Node.Obfs
		}
		if hy2Node.ObfsPassword != "" {
			clashNode["obfs-password"] = hy2Node.ObfsPassword
		}
		if hy2Node.SNI != "" {
			clashNode["sni"] = hy2Node.SNI
		}
		if hy2Node.SkipCertVerify {
			clashNode["skip-cert-verify"] = hy2Node.SkipCertVerify
		}
		if len(hy2Node.ALPN) > 0 {
			clashNode["alpn"] = hy2Node.ALPN
		}
		if hy2Node.Ca != "" {
			clashNode["ca"] = hy2Node.Ca
		}
		if hy2Node.CaStr != "" {
			clashNode["ca-str"] = hy2Node.CaStr
		}
	case "snell":
		snellNode := node.(*SnellProxy)
		clashNode["server"] = snellNode.Server
		clashNode["port"] = snellNode.Port
		clashNode["psk"] = snellNode.PSK
		clashNode["version"] = snellNode.Version
		clashNode["obfs"] = snellNode.Obfs
		clashNode["obfs-param"] = snellNode.ObfsParam
		clashNode["udp"] = snellNode.UDP
		clashNode["skip-cert-verify"] = snellNode.SkipCertVerify
	}

	return clashNode
}

func ClashToString(proxyList ProxyList) string {
	var clashStrings strings.Builder
	clashStrings.WriteString("proxies:\n")

	for _, node := range proxyList {
		// if !node.IsValid() {
		// 	continue
		// }

		clashNode := ProxieToClash(node)
		jsonData, err := json.Marshal(clashNode)
		if err != nil {
			log.LogError("JSON marshal error:", err)
		}

		// 追加到输出字符串中
		clashStrings.WriteString("- " + string(jsonData) + "\n")
	}

	if clashStrings.Len() == 9 { // 如果没有 proxy，添加无效的 NULL 节点，防止 Clash 对空节点的 Provider 报错
		clashStrings.WriteString("- {\"name\":\"NULL\",\"server\":\"NULL\",\"port\":11708,\"type\":\"ssr\",\"country\":\"NULL\",\"password\":\"sEscPBiAD9K$\\u0026@79\",\"cipher\":\"aes-256-cfb\",\"protocol\":\"origin\",\"protocol-param\":\"NULL\",\"obfs\":\"http_simple\"}")
	}
	return clashStrings.String()
}
