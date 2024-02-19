package proxy

import (
	"errors"
	"net/url"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/tool"
)

func (proxy *Proxy) trojanConstruct(group, remarks, server, port, password, network, host,
	path string, tlssecure bool, udp, tfo, scv, tls13 *bool) {
	proxy.commonConstruct("trojan", group, remarks, server, port, udp, tfo, scv, tls13)
	proxy.Password = password
	proxy.Host = host
	proxy.TLSSecure = tlssecure
	if network == "" {
		proxy.TransferProtocol = "tcp"
	} else {
		proxy.TransferProtocol = network
	}
	proxy.Path = path
}

func explodeTrojan(trojan string) (Proxy, error) {
	var server, port, psk, addition, remark, host, path, network string
	var tfo, scv bool

	u, err := url.Parse(trojan)
	if err != nil {
		return Proxy{}, err
	}

	// 分解主配置和附加参数
	remark = u.Fragment
	psk = u.User.String()
	server = u.Hostname()
	port = u.Port()
	if port == "0" || port == "" {
		return Proxy{}, errors.New("trojan config port is 0")
	}

	addition = u.RawQuery
	host = tool.GetUrlArg(addition, "sni")
	if host == "" {
		host = tool.GetUrlArg(addition, "peer")
	}

	tfo = false
	if tool.GetUrlArg(addition, "tfo") == "true" {
		tfo = true
	}
	scv = false
	if tool.GetUrlArg(addition, "allowinsecure") == "true" {
		scv = true
	}

	if tool.GetUrlArg(addition, "ws") == "1" {
		path = tool.GetUrlArg(addition, "wspath")
		network = "ws"
	} else if tool.GetUrlArg(addition, "type") == "ws" {
		path = tool.GetUrlArg(addition, "path")
		if strings.HasPrefix(path, "%2F") {
			path = url.QueryEscape(path)
		}
		network = "ws"
	}

	if remark == "" {
		remark = server + ":" + port
	}

	// 构造节点
	proxy := Proxy{}
	proxy.trojanConstruct("trojan_group", remark, server, port, psk, network, host, path, true, nil, &tfo, &scv, nil)
	return proxy, nil
}

// func trojanConf(s string) (ClashTrojan, error) {
// 	s, err := url.PathUnescape(s)
// 	if err != nil {
// 		return ClashTrojan{}, err
// 	}

// 	findStr := trojanReg.FindStringSubmatch(s)
// 	if len(findStr) == 6 {
// 		return ClashTrojan{
// 			Name:     findStr[5],
// 			Type:     "trojan",
// 			Server:   findStr[2],
// 			Password: findStr[1],
// 			Sni:      findStr[4],
// 			Port:     findStr[3],
// 		}, nil
// 	}

// 	findStr = trojanReg2.FindStringSubmatch(s)
// 	if len(findStr) < 5 {
// 		return ClashTrojan{}, errors.New("trojan连接参数少于5个")
// 	}

// 	return ClashTrojan{
// 		Name:     findStr[4],
// 		Type:     "trojan",
// 		Server:   findStr[2],
// 		Password: findStr[1],
// 		Port:     findStr[3],
// 	}, nil
// }
