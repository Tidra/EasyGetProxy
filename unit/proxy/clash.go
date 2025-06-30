package proxy

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/ghodss/yaml"
)

func ExplodeClash(clash string) (ProxyList, error) {
	proxyList := make(ProxyList, 0)
	re := regexp.MustCompile(`((?m)^(?:Proxy|proxies):$\s(?:(?:^ +?.*$| *?-.*$|)\s?)+)`)
	reResult := re.FindStringSubmatch(clash)
	if len(reResult) < 1 {
		return nil, errors.New("未找到有效的节点信息")
	}
	clash = re.FindStringSubmatch(clash)[1]

	yamlnode := make(map[string]interface{})
	jsond, err := yaml.YAMLToJSON([]byte(clash))
	if err != nil {
		return proxyList, err
	}
	json.Unmarshal(jsond, &yamlnode)

	section := "Proxy"
	if _, ok := yamlnode["proxies"]; ok {
		section = "proxies"
	}

	for _, v := range yamlnode[section].([]interface{}) {
		var proxyType, remark, server, port, cipher, password string // common
		var id, aid, net, path, host, edge, tls, sni string          // vmess
		var plugin string                                            // ss
		var protocol, protoparam, obfs, obfsparam string             // ssr
		var user string                                              // socks
		var udp, tfo, scv bool
		var singleProxy map[string]interface{}

		singleProxy = v.(map[string]interface{})
		tool.Base64DecodeByte(clash)
		proxyType = tool.SafeAsString(singleProxy, "type")
		remark = tool.SafeAsString(singleProxy, "name")
		server = tool.SafeAsString(singleProxy, "server")
		port = tool.SafeAsString(singleProxy, "port")
		if port == "" || port == "0" {
			continue
		}
		udp = tool.SafeAsBool(singleProxy, "udp")
		scv = tool.SafeAsBool(singleProxy, "skip-cert-verify")

		var proxy Proxy
		switch proxyType {
		case "vmess":
			id = tool.SafeAsString(singleProxy, "uuid")
			aid = tool.SafeAsString(singleProxy, "alterId")
			cipher = tool.SafeAsString(singleProxy, "cipher")
			net = tool.SafeAsString(singleProxy, "network")
			if net == "" {
				net = "tcp"
			}
			sni = tool.SafeAsString(singleProxy, "servername")
			switch net {
			case "http":
				path = tool.SafeAsString(singleProxy, "http-opts", "path", "0")
				host = tool.SafeAsString(singleProxy, "http-opts", "headers", "Host")
				edge = ""
			case "ws":
				if singleProxy["ws-opts"] != nil {
					path = tool.SafeAsString(singleProxy, "ws-opts", "path")
					host = tool.SafeAsString(singleProxy, "ws-opts", "headers", "Host")
					if host == "" {
						host = tool.SafeAsString(singleProxy, "ws-opts", "headers", "HOST")
					}
					edge = tool.SafeAsString(singleProxy, "ws-opts", "headers", "Edge")
				} else {
					path = tool.SafeAsString(singleProxy, "ws-path")
					host = tool.SafeAsString(singleProxy, "ws-headers", "Host")
					edge = tool.SafeAsString(singleProxy, "ws-headers", "Edge")
				}
			case "h2":
				path = tool.SafeAsString(singleProxy, "h2-opts", "path")
				host = tool.SafeAsString(singleProxy, "h2-opts", "host")
			case "grpc":
				path = tool.SafeAsString(singleProxy, "grpc-opts", "grpc-service-name")
				host = tool.SafeAsString(singleProxy, "servername")
			}

			if tool.SafeAsBool(singleProxy, "tls") {
				tls = "tls"
			} else {
				tls = ""
			}

			vmessProxy := &Vmess{}
			vmessProxy.vmessConstruct("vmess_group", remark, server, port, "", id, aid, net, cipher, path, host, edge, tls, sni, &udp, &tfo, &scv, nil)
			proxy = vmessProxy

		case "ss":
			cipher = tool.SafeAsString(singleProxy, "cipher")
			password = tool.SafeAsString(singleProxy, "password")
			pluginOpts := ""

			if singleProxy["plugin"] != nil {
				switch tool.SafeAsString(singleProxy, "plugin") {
				case "obfs":
					plugin = "obfs-local"
					if singleProxy["plugin-opts"] != nil {
						pluginOpts = "obfs=" + tool.SafeAsString(singleProxy, "plugin-opts", "mode")
						if host := tool.SafeAsString(singleProxy, "plugin-opts", "host"); host != "" {
							pluginOpts += ";obfs-host=" + host
						}
					}
				case "v2ray-plugin":
					plugin = "v2ray-plugin"
					if singleProxy["plugin-opts"] != nil {
						pluginOpts = "obfs=" + tool.SafeAsString(singleProxy, "plugin-opts", "mode")
						if tool.SafeAsBool(singleProxy, "plugin-opts", "tls") {
							pluginOpts += ";tls"
						}
						if host := tool.SafeAsString(singleProxy, "plugin-opts", "host"); host != "" {
							pluginOpts += ";host=" + host
						}
						if path := tool.SafeAsString(singleProxy, "plugin-opts", "path"); path != "" {
							pluginOpts += ";path=" + path
						}
						if tool.SafeAsBool(singleProxy, "plugin-opts", "mux") {
							pluginOpts += ";mux=4"
						}
					}
				}
			} else if singleProxy["obfs"] != nil {
				plugin = "obfs-local"
				pluginOpts = "obfs=" + tool.SafeAsString(singleProxy, "plugin-opts", "mode")
				if host := tool.SafeAsString(singleProxy, "plugin-opts", "host"); host != "" {
					pluginOpts += ";obfs-host=" + host
				}
			}

			// support for go-shadowsocks2
			if cipher == "AEAD_CHACHA20_POLY1305" {
				cipher = "chacha20-ietf-poly1305"
			} else if strings.Contains(cipher, "AEAD") {
				cipher = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(cipher, "AEAD_", ""), "_", "-"))
			}

			ssProxy := &SSProxy{}
			ssProxy.ssConstruct("ss_group", remark, server, port, password, cipher, plugin, pluginOpts)
			proxy = ssProxy

		case "socks5":
			user = tool.SafeAsString(singleProxy, "username")
			password = tool.SafeAsString(singleProxy, "password")

			socks5Proxy := &Socks5Proxy{}
			socks5Proxy.socks5Construct("socks_group", remark, server, port, user, password)
			proxy = socks5Proxy

		case "ssr":
			cipher = tool.SafeAsString(singleProxy, "cipher")
			if cipher == "dummy" {
				cipher = "none"
			}
			password = tool.SafeAsString(singleProxy, "password")
			protocol = tool.SafeAsString(singleProxy, "protocol")
			obfs = tool.SafeAsString(singleProxy, "obfs")
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

			ssrProxy := &SSRProxy{}
			ssrProxy.ssrConstruct("ssr_group", remark, server, port, protocol, cipher, obfs, password, obfsparam, protoparam, &udp)
			proxy = ssrProxy

		case "http":
			user = tool.SafeAsString(singleProxy, "username")
			password = tool.SafeAsString(singleProxy, "password")
			tls = tool.SafeAsString(singleProxy, "tls")

			httpProxy := &HTTPProxy{}
			httpProxy.httpConstruct("http_group", remark, server, port, user, password, tls == "true")
			proxy = httpProxy

		case "trojan":
			password = tool.SafeAsString(singleProxy, "password")
			host = tool.SafeAsString(singleProxy, "sni")
			net = tool.SafeAsString(singleProxy, "network")
			switch net {
			case "grpc":
				path = tool.SafeAsString(singleProxy, "grpc-opts", "grpc-service-name")
			case "ws":
				path = tool.SafeAsString(singleProxy, "ws-opts", "path")
			default:
				net = "tcp"
			}

			trojanProxy := &TrojanProxy{}
			trojanProxy.trojanConstruct("trojan_group", remark, server, port, password, net, host, path, true, &udp, &tfo, &scv)
			proxy = trojanProxy
		case "vless":
			id = tool.SafeAsString(singleProxy, "uuid")
			net = tool.SafeAsString(singleProxy, "network")
			if net == "" {
				net = "tcp"
			}
			sni = tool.SafeAsString(singleProxy, "servername")
			flow := tool.SafeAsString(singleProxy, "flow")
			security := tool.SafeAsString(singleProxy, "security")
			alpn := tool.SafeAsString(singleProxy, "alpn")
			clientFingerprint := tool.SafeAsString(singleProxy, "client-fingerprint")

			pk := ""
			sid := ""
			if singleProxy["reality-opts"] != nil {
				security = "reality"
				pk = tool.SafeAsString(singleProxy, "reality-opts", "public-key")
				sid = tool.SafeAsString(singleProxy, "reality-opts", "short-id")
			}

			if tool.SafeAsBool(singleProxy, "tls") {
				security = "tls"
			}

			vlessProxy := &VlessProxy{}
			vlessProxy.Group = "vless_group"
			vlessProxy.Name = remark
			vlessProxy.Server = server
			vlessProxy.Port = tool.SafeAsInt(singleProxy, "port")
			vlessProxy.UUID = id
			vlessProxy.Flow = flow
			vlessProxy.Transport = net
			vlessProxy.Security = security
			vlessProxy.SNI = sni
			vlessProxy.ALPN = strings.Split(alpn, ",")
			vlessProxy.Path = path
			vlessProxy.Host = host
			vlessProxy.UDP = udp
			vlessProxy.SkipCertVerify = scv
			vlessProxy.ClientFingerprint = clientFingerprint
			if security == "reality" {
				vlessProxy.RealityOpts.PublicKey = pk
				vlessProxy.RealityOpts.ShortID = sid
			}

			switch net {
			case "ws":
				// 尝试将 ws-opts 转换为 map[string]interface{}
				if wsopts, ok := singleProxy["ws-opts"].(map[string]interface{}); ok {
					// 获取 path 字段值
					if path, ok := wsopts["path"].(string); ok {
						vlessProxy.WSOpts.Path = path
					}
					// 尝试将 headers 转换为 map[string]interface{}
					if headers, ok := wsopts["headers"].(map[string]interface{}); ok {
						vlessProxy.WSOpts.Headers = make(map[string]string)
						for k, v := range headers {
							// 使用类型断言将值转换为 string
							if str, ok := v.(string); ok {
								vlessProxy.WSOpts.Headers[k] = str
							}
						}
					}
				}
			case "grpc":
				vlessProxy.GRPCOpts.ServiceName = tool.SafeAsString(singleProxy, "grpc-opts", "grpc-service-name")
			}

			proxy = vlessProxy
		case "hysteria":
			// 优先获取 auth_str，若为空则获取 auth-str
			auth := tool.SafeAsString(singleProxy, "auth_str")
			if auth == "" {
				auth = tool.SafeAsString(singleProxy, "auth-str")
			}
			up := tool.SafeAsString(singleProxy, "up")
			down := tool.SafeAsString(singleProxy, "down")
			sni := tool.SafeAsString(singleProxy, "sni")
			alpn := tool.SafeAsString(singleProxy, "alpn")
			protocol := tool.SafeAsString(singleProxy, "protocol")
			if protocol == "" {
				protocol = "udp"
			}
			skipCertVerify := tool.SafeAsBool(singleProxy, "skip-cert-verify")

			// 处理 alpn 为字符串切片
			var alpnSlice []string
			if alpn != "" {
				alpnSlice = strings.Split(alpn, ",")
			}

			hysteriaProxy := &HysteriaProxy{}
			hysteriaProxy.Group = "hysteria_group"
			hysteriaProxy.Name = remark
			hysteriaProxy.Server = server
			hysteriaProxy.Port = tool.SafeAsInt(singleProxy, "port")
			hysteriaProxy.Auth = auth
			hysteriaProxy.Up = up
			hysteriaProxy.Down = down
			hysteriaProxy.SNI = sni
			hysteriaProxy.ALPN = alpnSlice
			hysteriaProxy.UDP = protocol == "udp"
			hysteriaProxy.SkipCertVerify = skipCertVerify
			proxy = hysteriaProxy
		case "hysteria2":
			auth := tool.SafeAsString(singleProxy, "password")
			obfs := tool.SafeAsString(singleProxy, "obfs")
			obfsPassword := tool.SafeAsString(singleProxy, "obfs-password")
			sni := tool.SafeAsString(singleProxy, "sni")
			insecure := tool.SafeAsBool(singleProxy, "skip-cert-verify")
			pinSHA256 := "" // 结构不匹配，置空

			hy2Proxy := &Hy2Proxy{}
			hy2Proxy.Group = "hy2_group"
			hy2Proxy.Name = remark
			hy2Proxy.Server = server
			hy2Proxy.Port = tool.SafeAsInt(singleProxy, "port")
			hy2Proxy.Auth = auth
			hy2Proxy.Obfs = obfs
			hy2Proxy.ObfsPassword = obfsPassword
			hy2Proxy.SNI = sni
			hy2Proxy.Insecure = insecure
			hy2Proxy.PinSHA256 = pinSHA256
			proxy = hy2Proxy
		case "snell":
			psk := tool.SafeAsString(singleProxy, "psk")
			version := tool.SafeAsInt(singleProxy, "version")
			obfs := tool.SafeAsString(singleProxy, "obfs")
			obfsParam := tool.SafeAsString(singleProxy, "obfs-param")

			snellProxy := &SnellProxy{}
			snellProxy.Group = "snell_group"
			snellProxy.Name = remark
			snellProxy.Server = server
			snellProxy.Port = tool.SafeAsInt(singleProxy, "port")
			snellProxy.PSK = psk
			snellProxy.Version = version
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
	case "ss":
		// TODO: 判断协议是否符合
		ssNode := node.(*SSProxy)
		clashNode["server"] = ssNode.Server
		clashNode["port"] = ssNode.Port
		clashNode["cipher"] = ssNode.EncryptMethod
		clashNode["password"] = ssNode.Password
		pluginString := strings.ReplaceAll(ssNode.PluginOption, ";", "&")
		switch ssNode.Plugin {
		case "simple-obfs", "obfs-local":
			clashNode["plugin"] = "obfs"
			pluginOpts := make(map[string]interface{})
			pluginOpts["mode"] = tool.GetUrlArg(pluginString, "obfs")
			pluginOpts["host"] = tool.GetUrlArg(pluginString, "obfs-host")
			clashNode["plugin-opts"] = pluginOpts
		case "v2ray-plugin":
			clashNode["plugin"] = "v2ray-plugin"
			pluginOpts := make(map[string]interface{})
			pluginOpts["mode"] = tool.GetUrlArg(pluginString, "mode")
			pluginOpts["host"] = tool.GetUrlArg(pluginString, "host")
			pluginOpts["path"] = tool.GetUrlArg(pluginString, "path")
			pluginOpts["tls"] = strings.Contains(pluginString, "tls")
			pluginOpts["mux"] = strings.Contains(pluginString, "mux")
			if ssNode.SkipCertVerify {
				pluginOpts["skip-cert-verify"] = ssNode.SkipCertVerify
			}
			clashNode["plugin-opts"] = pluginOpts
		}
	case "vmess":
		vmessNode := node.(*Vmess)
		clashNode["server"] = vmessNode.Server
		clashNode["port"] = vmessNode.Port
		clashNode["uuid"] = vmessNode.UUID
		clashNode["alterId"] = vmessNode.AlterID
		clashNode["cipher"] = vmessNode.EncryptMethod
		clashNode["tls"] = vmessNode.TLSSecure
		clashNode["udp"] = vmessNode.UDP
		clashNode["skip-cert-verify"] = vmessNode.SkipCertVerify
		clashNode["servername"] = vmessNode.ServerName
		switch vmessNode.TransferProtocol {
		case "ws":
			clashNode["network"] = vmessNode.TransferProtocol
			clashNode["ws-opts"] = map[string]interface{}{
				"path": vmessNode.Path,
				"headers": map[string]interface{}{
					"Host": vmessNode.Host,
					"Edge": vmessNode.Edge,
				},
			}
		case "http":
			clashNode["network"] = vmessNode.TransferProtocol
			clashNode["http-opts"] = map[string]interface{}{
				"method": "GET",
				"path":   vmessNode.Path,
				"Host":   vmessNode.Host,
				"Edge":   vmessNode.Edge,
			}
		case "h2":
			clashNode["network"] = vmessNode.TransferProtocol
			clashNode["h2-opts"] = map[string]interface{}{
				"path": vmessNode.Path,
				"host": vmessNode.Host,
			}
		case "grpc":
			clashNode["network"] = vmessNode.TransferProtocol
			clashNode["servername"] = vmessNode.Host
			clashNode["grpc-opts"] = map[string]interface{}{"grpc-service-name": vmessNode.Path}
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
		clashNode["protocol"] = ssrNode.Protocol
		clashNode["obfs"] = ssrNode.OBFS
		clashNode["protocol-param"] = ssrNode.ProtocolParam
		clashNode["obfs-param"] = ssrNode.OBFSParam
	case "socks5":
		socks5Node := node.(*Socks5Proxy)
		clashNode["server"] = socks5Node.Server
		clashNode["port"] = socks5Node.Port
		clashNode["username"] = socks5Node.Username
		clashNode["password"] = socks5Node.Password
		clashNode["skip-cert-verify"] = socks5Node.SkipCertVerify
	case "http", "https":
		httpNode := node.(*HTTPProxy)
		clashNode["server"] = httpNode.Server
		clashNode["port"] = httpNode.Port
		clashNode["username"] = httpNode.Username
		clashNode["password"] = httpNode.Password
		clashNode["tls"] = httpNode.TLSSecure
		clashNode["skip-cert-verify"] = httpNode.SkipCertVerify
	case "trojan":
		trojanNode := node.(*TrojanProxy)
		clashNode["server"] = trojanNode.Server
		clashNode["port"] = trojanNode.Port
		clashNode["password"] = trojanNode.Password
		clashNode["sni"] = trojanNode.Host
		clashNode["udp"] = trojanNode.UDP
		clashNode["skip-cert-verify"] = trojanNode.SkipCertVerify
		switch trojanNode.TransferProtocol {
		case "grpc":
			clashNode["network"] = trojanNode.TransferProtocol
			clashNode["grpc-opts"] = map[string]interface{}{"grpc-service-name": trojanNode.Path}
		case "ws":
			clashNode["network"] = trojanNode.TransferProtocol
			clashNode["ws-opts"] = map[string]interface{}{
				"path": trojanNode.Path,
				"headers": map[string]interface{}{
					"Host": trojanNode.Host,
				},
			}
		}
	case "vless":
		vlessNode := node.(*VlessProxy)
		clashNode["server"] = vlessNode.Server
		clashNode["port"] = vlessNode.Port
		clashNode["uuid"] = vlessNode.UUID
		clashNode["tls"] = vlessNode.Security == "tls" || vlessNode.Security == "reality"
		clashNode["udp"] = vlessNode.UDP
		clashNode["skip-cert-verify"] = vlessNode.SkipCertVerify
		clashNode["flow"] = vlessNode.Flow
		clashNode["network"] = vlessNode.Transport
		clashNode["servername"] = vlessNode.SNI
		clashNode["client-fingerprint"] = vlessNode.ClientFingerprint
		if len(vlessNode.ALPN) > 0 {
			clashNode["alpn"] = vlessNode.ALPN
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

		switch vlessNode.Transport {
		case "ws":
			ws := map[string]interface{}{
				"path":    vlessNode.WSOpts.Path,
				"headers": map[string]interface{}{},
			}
			for k, v := range vlessNode.WSOpts.Headers {
				ws["headers"].(map[string]interface{})[k] = v
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
		if hysteriaNode.Auth != "" {
			clashNode["auth_str"] = hysteriaNode.Auth
		}
		clashNode["up"] = hysteriaNode.Up
		clashNode["down"] = hysteriaNode.Down
		clashNode["sni"] = hysteriaNode.SNI
		if len(hysteriaNode.ALPN) > 0 {
			clashNode["alpn"] = hysteriaNode.ALPN
		}
		// 根据 UDP 字段设置 protocol
		if hysteriaNode.UDP {
			clashNode["protocol"] = "udp"
		}
		clashNode["skip-cert-verify"] = hysteriaNode.SkipCertVerify
		// 若 HysteriaProxy 结构体无对应字段，以下属性不添加到 clashNode
		// clashNode["disable_mtu_discovery"] = hysteriaNode.DisableMTUDiscovery
		// if hysteriaNode.Fingerprint != "" {
		// 	clashNode["fingerprint"] = hysteriaNode.Fingerprint
		// }
		// clashNode["fast-open"] = hysteriaNode.FastOpen
	case "hysteria2":
		hy2Node := node.(*Hy2Proxy)
		clashNode["server"] = hy2Node.Server
		clashNode["port"] = hy2Node.Port
		clashNode["password"] = hy2Node.Auth
		if hy2Node.Obfs != "" {
			clashNode["obfs"] = hy2Node.Obfs
		}
		if hy2Node.ObfsPassword != "" {
			clashNode["obfs-password"] = hy2Node.ObfsPassword
		}
		if hy2Node.SNI != "" {
			clashNode["sni"] = hy2Node.SNI
		}
		if hy2Node.Insecure {
			clashNode["skip-cert-verify"] = hy2Node.Insecure
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
