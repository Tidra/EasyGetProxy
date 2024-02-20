package proxy

import (
	"encoding/json"
	"regexp"

	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/ghodss/yaml"
)

func explodeClash(clash string) error {
	re := regexp.MustCompile(`((?m)^(?:Proxy|proxies):$\s(?:(?:^ +?.*$| *?-.*$|)\s?)+)`)
	clash = re.FindStringSubmatch(clash)[1]

	yamlnode := make(map[string]interface{})
	jsond, err := yaml.YAMLToJSON([]byte(clash))
	json.Unmarshal(jsond, &yamlnode)
	if err != nil {
		return err
	}

	var proxytype, ps, server, port, cipher, group, password string
	var typeStr, id, aid, net, path, host, edge, tls, sni string
	var plugin, pluginopts, pluginopts_mode, pluginopts_host, pluginopts_mux string
	var protocol, protoparam, obfs, obfsparam string
	var user string
	var ip, ipv6, private_key, public_key, mtu string
	var dns_server []string
	var udp, tfo, scv bool
	var singleproxy map[string]interface{}
	section := "Proxy"
	if _, ok := yamlnode["proxies"]; ok {
		section = "proxies"
	}

	for _, v := range yamlnode[section].([]interface{}) {

		log.LogInfo("Info %+v", v)
		singleproxy = v.(map[string]interface{})
		// log.LogInfo("Info %+v", singleproxy)
		tool.Base64DecodeByte(clash)
		proxytype = tool.SafeAsString(singleproxy, "type")
		ps = tool.SafeAsString(singleproxy, "name")
		server = tool.SafeAsString(singleproxy, "server")
		port = tool.SafeAsString(singleproxy, "port")
		if port == "" || port == "0" {
			continue
		}
		udp = tool.SafeAsBool(singleproxy, "udp")
		scv = tool.SafeAsBool(singleproxy, "skip-cert-verify")
		switch proxytype {
		case "vmess":
			group = "V2RAY_DEFAULT_GROUP"
			id = tool.SafeAsString(singleproxy, "uuid")
			aid = tool.SafeAsString(singleproxy, "alterId")
			cipher = tool.SafeAsString(singleproxy, "cipher")
			net = tool.SafeAsString(singleproxy, "network")
			if net == "" {
				net = "tcp"
			}
			sni = tool.SafeAsString(singleproxy, "servername")
			switch net {
			case "http":
				path = tool.SafeAsString(singleproxy["http-opts"].(map[string]interface{})["path"].(map[string]interface{}), "0")
				host = tool.SafeAsString(singleproxy["http-opts"].(map[string]interface{})["headers"].(map[string]interface{}), "Host")
				edge = ""
				break
			case "ws":
				if singleproxy["ws-opts"] != nil {
					path = tool.SafeAsString(singleproxy["ws-opts"].(map[string]interface{}), "path")
					if path == "" {
						path = "/"
					}
					host = tool.SafeAsString(singleproxy["ws-opts"].(map[string]interface{})["headers"].(map[string]interface{}), "Host")
					edge = tool.SafeAsString(singleproxy["ws-opts"].(map[string]interface{})["headers"].(map[string]interface{}), "Edge")
				} else {
					path = tool.SafeAsString(singleproxy, "ws-path")
					host = tool.SafeAsString(singleproxy["ws-headers"].(map[string]interface{}), "Host")
					edge = tool.SafeAsString(singleproxy["ws-headers"].(map[string]interface{}), "Edge")
				}
				break
			case "h2":
				path = tool.SafeAsString(singleproxy, "h2-opts")
				host = tool.SafeAsString(singleproxy["h2-opts"].(map[string]interface{}), "Host")

			}
		}
	}
	return nil
}
