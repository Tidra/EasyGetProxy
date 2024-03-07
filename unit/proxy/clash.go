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
	json.Unmarshal(jsond, &yamlnode)
	if err != nil {
		return proxyList, err
	}

	section := "Proxy"
	if _, ok := yamlnode["proxies"]; ok {
		section = "proxies"
	}

	for _, v := range yamlnode[section].([]interface{}) {
		var proxyType, remark, server, port, cipher, password string //common
		var id, aid, net, path, host, edge, tls, sni string          //vmess
		var plugin string                                            //ss
		var protocol, protoparam, obfs, obfsparam string             //ssr
		var user string                                              //socks
		var udp, tfo, scv bool
		var singleProxy map[string]interface{}

		proxy := Proxy{}
		// log.LogInfo("Info %+v", v)
		singleProxy = v.(map[string]interface{})
		// log.LogInfo("Info %+v", singleProxy)
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

			proxy.vmessConstruct("vmess_group", remark, server, port, "", id, aid, net, cipher, path, host, edge, tls, sni, &udp, &tfo, &scv, nil)

		case "ss":
			cipher = tool.SafeAsString(singleProxy, "cipher")
			password = tool.SafeAsString(singleProxy, "password")
			// pluginOpts := new(PluginOpts)
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
						// pluginOpts.Mode = tool.SafeAsString(singleProxy, "plugin-opts", "mode")
						// pluginOpts.Host = tool.SafeAsString(singleProxy, "plugin-opts", "host")
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
						// pluginOpts.Mode = tool.SafeAsString(singleProxy, "plugin-opts", "mode")
						// pluginOpts.Host = tool.SafeAsString(singleProxy, "plugin-opts", "host")
						// pluginOpts.Tls = tool.SafeAsBool(singleProxy, "plugin-opts", "tls")
						// pluginOpts.Path = tool.SafeAsString(singleProxy, "plugin-opts", "path")
						// pluginOpts.Mux = tool.SafeAsBool(singleProxy, "plugin-opts", "mux")
					}
				}
			} else if singleProxy["obfs"] != nil {
				plugin = "obfs-local"
				pluginOpts = "obfs=" + tool.SafeAsString(singleProxy, "plugin-opts", "mode")
				if host := tool.SafeAsString(singleProxy, "plugin-opts", "host"); host != "" {
					pluginOpts += ";obfs-host=" + host
				}
				// pluginOpts.Mode = tool.SafeAsString(singleProxy, "obfs")
				// pluginOpts.Host = tool.SafeAsString(singleProxy, "obfs-host")
			}

			//support for go-shadowsocks2
			if cipher == "AEAD_CHACHA20_POLY1305" {
				cipher = "chacha20-ietf-poly1305"
			} else if strings.Contains(cipher, "AEAD") {
				cipher = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(cipher, "AEAD_", ""), "_", "-"))
			}
			proxy.ssConstruct("ss_group", remark, server, port, password, cipher, plugin, pluginOpts, &udp, &tfo, &scv, nil)

		case "socks5":
			user = tool.SafeAsString(singleProxy, "username")
			password = tool.SafeAsString(singleProxy, "password")
			proxy.socksConstruct("socks_group", remark, server, port, user, password, nil, nil, nil)

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
			proxy.ssrConstruct("ssr_group", remark, server, port, protocol, cipher, obfs, password, obfsparam, protoparam, &udp, &tfo, &scv)

		case "http":
			user = tool.SafeAsString(singleProxy, "username")
			password = tool.SafeAsString(singleProxy, "password")
			tls = tool.SafeAsString(singleProxy, "tls")
			proxy.httpConstruct("http_group", remark, server, port, user, password, tls == "true", &tfo, &scv, nil)

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
			proxy.trojanConstruct("trojan_group", remark, server, port, password, net, host, path, true, &udp, &tfo, &scv, nil)
		}
		if !proxy.IsEmpty() {
			proxyList = append(proxyList, proxy)
		}
	}
	return proxyList, nil
}

func ProxieToClash(node Proxy) map[string]any {
	clashNode := make(map[string]interface{})
	clashNode["name"] = node.Name
	clashNode["server"] = node.Server
	clashNode["port"] = node.Port
	clashNode["type"] = node.Type

	// TODO: 判断空值是否输出
	// https://github.com/tindy2013/subconverter/blob/master/src/generator/config/subexport.cpp#L227
	switch node.Type {
	case "ss":
		// TODO: 判断协议是否符合
		clashNode["cipher"] = node.EncryptMethod
		clashNode["password"] = node.Password
		pluginString := strings.ReplaceAll(node.PluginOption, ";", "&")
		switch node.Plugin {
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
			if node.SkipCertVerify {
				pluginOpts["skip-cert-verify"] = node.SkipCertVerify
			}
			clashNode["plugin-opts"] = pluginOpts
		}
		// if node.PluginOption.Path != "" || node.PluginOption.Tls || node.PluginOption.SkipCertVerify || node.PluginOption.Mux {
		// 	clashNode["plugin-opts"] = map[string]interface{}{
		// 		"mode":             node.PluginOption.Mode,
		// 		"host":             node.PluginOption.Host,
		// 		"tls":              node.PluginOption.Tls,
		// 		"path":             node.PluginOption.Path,
		// 		"skip-cert-verify": node.PluginOption.SkipCertVerify,
		// 		"mux":              node.PluginOption.Mux,
		// 	}
		// } else {
		// 	clashNode["plugin-opts"] = map[string]interface{}{
		// 		"mode": node.PluginOption.Mode,
		// 		"host": node.PluginOption.Host,
		// 	}
		// }
	case "vmess":
		clashNode["uuid"] = node.UUID
		clashNode["alterId"] = node.AlterID
		clashNode["cipher"] = node.EncryptMethod
		clashNode["tls"] = node.TLSSecure
		clashNode["udp"] = node.UDP
		clashNode["skip-cert-verify"] = node.SkipCertVerify
		clashNode["servername"] = node.ServerName
		switch node.TransferProtocol {
		case "ws":
			clashNode["network"] = node.TransferProtocol
			clashNode["ws-opts"] = map[string]interface{}{
				"path": node.Path,
				"headers": map[string]interface{}{
					"Host": node.Host,
					"Edge": node.Edge,
				},
			}
			// TODO: 不同的clash的ws写法
			// clashNode["ws-path"] = node.Path
			// if node.Host != "" && node.Edge != "" {
			// 	clashNode["ws-headers"] = map[string]interface{}{"Host": node.Host, "Edge": node.Edge}
			// }
		case "http":
			clashNode["network"] = node.TransferProtocol
			clashNode["http-opts"] = map[string]interface{}{
				"method": "GET",
				"path":   node.Path,
				"Host":   node.Host,
				"Edge":   node.Edge,
			}
		case "h2":
			clashNode["network"] = node.TransferProtocol
			clashNode["h2-opts"] = map[string]interface{}{
				"path": node.Path,
				"host": node.Host,
			}
		case "grpc":
			clashNode["network"] = node.TransferProtocol
			clashNode["servername"] = node.Host
			clashNode["grpc-opts"] = map[string]interface{}{"grpc-service-name": node.Path}
		}
	case "ssr":
		// TODO: 判断协议是否符合
		if node.EncryptMethod == "none" {
			clashNode["cipher"] = "dummy"
		} else {
			clashNode["cipher"] = node.EncryptMethod
		}
		clashNode["password"] = node.Password
		clashNode["protocol"] = node.Protocol
		clashNode["obfs"] = node.OBFS
		clashNode["protocol-param"] = node.ProtocolParam
		clashNode["obfs-param"] = node.OBFSParam
		// TODO: clashR支持
		// clashNode["protocolparam"] = node.ProtocolParam
		// clashNode["obfsparam"] = node.OBFSParam
	case "socks5":
		clashNode["username"] = node.Username
		clashNode["password"] = node.Password
		clashNode["skip-cert-verify"] = node.SkipCertVerify
	case "http", "https":
		clashNode["username"] = node.Username
		clashNode["password"] = node.Password
		clashNode["tls"] = node.TLSSecure
		clashNode["skip-cert-verify"] = node.SkipCertVerify
	case "trojan":
		clashNode["password"] = node.Password
		clashNode["sni"] = node.Host
		clashNode["udp"] = node.UDP
		clashNode["skip-cert-verify"] = node.SkipCertVerify
		switch node.TransferProtocol {
		case "grpc":
			clashNode["network"] = node.TransferProtocol
			clashNode["grpc-opts"] = map[string]interface{}{"grpc-service-name": node.Path}
		case "ws":
			clashNode["network"] = node.TransferProtocol
			clashNode["ws-opts"] = map[string]interface{}{
				"path": node.Path,
				"headers": map[string]interface{}{
					"Host": node.Host,
				},
			}
		}
	}

	return clashNode
}

func ClashToString(proxyList ProxyList) string {
	var clashStrings strings.Builder
	clashStrings.WriteString("proxies:\n")

	for _, node := range proxyList {
		if !node.IsValid {
			continue
		}

		clashNode := ProxieToClash(node)
		jsonData, err := json.Marshal(clashNode)
		if err != nil {
			log.LogError("JSON marshal error:", err)
		}

		// 追加到输出字符串中
		clashStrings.WriteString("- " + string(jsonData) + "\n")
	}

	if clashStrings.Len() == 9 { //如果没有proxy，添加无效的NULL节点，防止Clash对空节点的Provider报错
		clashStrings.WriteString("- {\"name\":\"NULL\",\"server\":\"NULL\",\"port\":11708,\"type\":\"ssr\",\"country\":\"NULL\",\"password\":\"sEscPBiAD9K$\\u0026@79\",\"cipher\":\"aes-256-cfb\",\"protocol\":\"origin\",\"protocol_param\":\"NULL\",\"obfs\":\"http_simple\"}")
	}
	return clashStrings.String()
}
