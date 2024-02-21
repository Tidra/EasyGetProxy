package proxy

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/ghodss/yaml"
)

func explodeClash(clash string) (ProxyList, error) {
	proxyList := make(ProxyList, 0)
	re := regexp.MustCompile(`((?m)^(?:Proxy|proxies):$\s(?:(?:^ +?.*$| *?-.*$|)\s?)+)`)
	clash = re.FindStringSubmatch(clash)[1]

	yamlnode := make(map[string]interface{})
	jsond, err := yaml.YAMLToJSON([]byte(clash))
	json.Unmarshal(jsond, &yamlnode)
	if err != nil {
		return proxyList, err
	}

	var proxyType, remark, server, port, cipher, password string //common
	var id, aid, net, path, host, edge, tls, sni string          //vmess
	var plugin string                                            //ss
	var protocol, protoparam, obfs, obfsparam string             //ssr
	var user string                                              //socks
	var udp, tfo, scv bool
	var singleProxy map[string]interface{}
	section := "Proxy"
	if _, ok := yamlnode["proxies"]; ok {
		section = "proxies"
	}

	for _, v := range yamlnode[section].([]interface{}) {
		proxy := Proxy{}
		log.LogInfo("Info %+v", v)
		singleProxy = v.(map[string]interface{})
		// log.LogInfo("Info %+v", singleproxy)
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
				path = tool.SafeAsString(singleProxy["http-opts"].(map[string]interface{})["path"].(map[string]interface{}), "0")
				host = tool.SafeAsString(singleProxy["http-opts"].(map[string]interface{})["headers"].(map[string]interface{}), "Host")
				edge = ""
			case "ws":
				if singleProxy["ws-opts"] != nil {
					path = tool.SafeAsString(singleProxy["ws-opts"].(map[string]interface{}), "path")
					if path == "" {
						path = "/"
					}
					host = tool.SafeAsString(singleProxy["ws-opts"].(map[string]interface{})["headers"].(map[string]interface{}), "Host")
					edge = tool.SafeAsString(singleProxy["ws-opts"].(map[string]interface{})["headers"].(map[string]interface{}), "Edge")
				} else {
					path = tool.SafeAsString(singleProxy, "ws-path")
					host = tool.SafeAsString(singleProxy["ws-headers"].(map[string]interface{}), "Host")
					edge = tool.SafeAsString(singleProxy["ws-headers"].(map[string]interface{}), "Edge")
				}
			case "h2":
				path = tool.SafeAsString(singleProxy["h2-opts"].(map[string]interface{}), "path")
				host = tool.SafeAsString(singleProxy["h2-opts"].(map[string]interface{}), "host")
			case "grpc":
				path = tool.SafeAsString(singleProxy["grpc-opts"].(map[string]interface{}), "grpc-service-name")
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
			pluginOpts := new(PluginOpts)

			if singleProxy["plugin"] != nil {
				switch tool.SafeAsString(singleProxy, "plugin") {
				case "obfs":
					plugin = "obfs-local"
					if singleProxy["plugin-opts"] != nil {
						pluginOpts.Mode = tool.SafeAsString(singleProxy["plugin-opts"].(map[string]interface{}), "mode")
						pluginOpts.Host = tool.SafeAsString(singleProxy["plugin-opts"].(map[string]interface{}), "host")
					}
				case "v2ray-plugin":
					plugin = "v2ray-plugin"
					if singleProxy["plugin-opts"] != nil {
						pluginOpts.Mode = tool.SafeAsString(singleProxy["plugin-opts"].(map[string]interface{}), "mode")
						pluginOpts.Host = tool.SafeAsString(singleProxy["plugin-opts"].(map[string]interface{}), "host")
						pluginOpts.Tls = tool.SafeAsBool(singleProxy["plugin-opts"].(map[string]interface{}), "host")
						pluginOpts.Path = tool.SafeAsString(singleProxy["plugin-opts"].(map[string]interface{}), "path")
						pluginOpts.Mux = tool.SafeAsBool(singleProxy["plugin-opts"].(map[string]interface{}), "mux")
					}
				}
			} else if singleProxy["obfs"] != nil {
				plugin = "obfs-local"
				pluginOpts.Mode = tool.SafeAsString(singleProxy, "obfs")
				pluginOpts.Host = tool.SafeAsString(singleProxy, "obfs-host")
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
				path = tool.SafeAsString(singleProxy["grpc-opts"].(map[string]interface{}), "grpc-service-name")
			case "ws":
				path = tool.SafeAsString(singleProxy["ws-opts"].(map[string]interface{}), "path")
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
