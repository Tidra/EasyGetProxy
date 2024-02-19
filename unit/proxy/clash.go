package proxy

import (
	"regexp"

	"github.com/Tidra/EasyGetProxy/unit/log"
	"gopkg.in/yaml.v2"
)

func explodeClash(clash string) error {
	r := regexp.MustCompile("^(?:Proxy|proxies):$\\s(?:(?:^ +?.*$| *?-.*$|)\\s?)+")
	clash = r.FindStringSubmatch(clash)[1]

	var yamlnode map[string]interface{}
	err := yaml.Unmarshal([]byte(clash), &yamlnode)
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

		singleproxy = v.(map[string]interface{})
		log.LogInfo("Info %+v", singleproxy)
		proxytype = tool.safeAsString(singleproxy, "type")
		ps = tool.safeAsString(singleproxy, "name")
		server = tool.safeAsString(singleproxy, "server")
		port = tool.safeAsString(singleproxy, "port")
		if port == "" || port == "0" {
			continue
		}
		udp = tool.safeAsBool(singleproxy, "udp")
		scv = tool.safeAsBool(singleproxy, "skip-cert-verify")
		switch proxytype {
		case "vmess":
			group = "V2RAY_DEFAULT_GROUP"
			id = tool.safeAsString(singleproxy, "uuid")
			aid = tool.safeAsString(singleproxy, "alterId")
			cipher = tool.safeAsString(singleproxy, "cipher")
			net = tool.safeAsString(singleproxy, "network")
			if net == "" {
				net = "tcp"
			}
			sni = tool.safeAsString(singleproxy, "servername")
			switch net {
			case "http":
				path = tool.safeAsString(singleproxy["http-opts"].(map[string]interface{})["path"].(map[string]interface{}), "0")
				host = tool.safeAsString(singleproxy["http-opts"].(map[string]interface{})["headers"].(map[string]interface{}), "Host")
				edge = ""
				break
			case "ws":
				if singleproxy["ws-opts"] != nil {
					path = tool.safeAsString(singleproxy["ws-opts"].(map[string]interface{}), "path")
					if path == "" {
						path = "/"
					}
					host = tool.safeAsString(singleproxy["ws-opts"].(map[string]interface{})["headers"].(map[string]interface{}), "Host")
					edge = tool.safeAsString(singleproxy["ws-opts"].(map[string]interface{})["headers"].(map[string]interface{}), "Edge")
				} else {
					path = tool.safeAsString(singleproxy, "ws-path")
					host = tool.safeAsString(singleproxy["ws-headers"].(map[string]interface{}), "Host")
					edge = tool.safeAsString(singleproxy["ws-headers"].(map[string]interface{}), "Edge")
				}
			}
		}
	}
}
