package proxy

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/spf13/cast"
)

type Vmess struct {
	Add  string `json:"add"`
	Aid  any    `json:"aid"`
	Host string `json:"host"`
	ID   string `json:"id"`
	Net  string `json:"net"`
	Path string `json:"path"`
	Port any    `json:"port"`
	PS   string `json:"ps"`
	TLS  string `json:"tls"`
	Type string `json:"type"`
	Sni  string `json:"sni"`
	V    any    `json:"v"`
}

func (proxy *Proxy) vmessConstruct(group, ps, add string, port any, fakeType, id string,
	aid any, net, cipher, path, host, edge, tls, sni string, udp, tfo, scv, tls13 *bool) {
	proxy.commonConstruct("vmess", group, ps, add, port, udp, tfo, scv, tls13)
	if id == "" {
		proxy.UUID = "00000000-0000-0000-0000-000000000000"
	} else {
		proxy.UUID = id
	}
	proxy.AlterID = cast.ToUint16(aid)
	proxy.EncryptMethod = cipher
	if net == "" {
		proxy.TransferProtocol = "tcp"
	} else {
		proxy.TransferProtocol = net
	}
	proxy.Edge = edge
	proxy.ServerName = sni

	if strings.EqualFold(net, "quic") {
		proxy.QUICSecure = host
		proxy.QUICSecret = path
	} else {
		if host == "" {
			proxy.Host = add
		} else {
			proxy.Host = strings.TrimSpace(host)
		}
		if path == "" {
			proxy.Path = "/"
		} else {
			proxy.Path = strings.TrimSpace(path)
		}
	}
	proxy.FakeType = fakeType
	proxy.TLSSecure = strings.EqualFold(tls, "tls")
}

func v2rConf(s string) (Proxy, error) {
	vmconfig, err := tool.Base64DecodeByte(s)
	if err != nil {
		return Proxy{}, err
	}
	vmess := Vmess{}
	err = json.Unmarshal(vmconfig, &vmess)
	if err != nil {
		log.LogError("v2ray config json unmarshal failed, err: %v", err)
		return Proxy{}, err
	}

	if cast.ToInt(vmess.Port) == 0 {
		return Proxy{}, errors.New("v2ray config port is 0")
	}

	host := vmess.Host
	path := ""
	switch cast.ToInt(vmess.V) {
	case 2:
		path = vmess.Path
	default: //包括1
		if host != "" {
			vArray := strings.Split(host, ";")
			if len(vArray) == 2 {
				host, path = vArray[0], vArray[1]
			}
		}
	}

	proxy := Proxy{}
	proxy.vmessConstruct("vmess_group", vmess.PS, vmess.Add, vmess.Port, vmess.Type, vmess.ID,
		vmess.Aid, vmess.Net, "auto", path, host, "", vmess.TLS, vmess.Sni, nil, nil, nil, nil)
	return proxy, nil

}

func explodeShadowrocket(rocket string) (Proxy, error) {
	var add, port, fakeType, id, aid, net, path, host, tls, cipher, remarks string

	u, err := url.Parse(rocket)
	if err != nil {
		return Proxy{}, err
	}

	// 分解主配置和附加参数
	configStr := u.Host
	addition := u.RawQuery

	configStr, err = tool.Base64DecodeString(configStr)
	if err != nil {
		return Proxy{}, err
	}

	// 使用正则解析参数
	regex := regexp.MustCompile(`(.*?):(.*?)@(.*?):(.*?)`)
	if regex.MatchString(configStr) {
		result := regex.FindStringSubmatch(configStr)[1:]
		cipher, id, add, port = result[0], result[1], result[2], result[3]
	} else {
		return Proxy{}, errors.New("vmess config not match: uuid, add, port")
	}

	if port == "0" {
		return Proxy{}, errors.New("vmess config port is 0")
	}

	// 解析 Addition
	remarks = url.QueryEscape(tool.GetUrlArg(addition, "remarks"))
	obfs := tool.GetUrlArg(addition, "obfs")

	if obfs == "websocket" {
		net = "ws"
		host = tool.GetUrlArg(addition, "obfsParam")
		path = tool.GetUrlArg(addition, "path")
	} else {
		net = tool.GetUrlArg(addition, "network")
		host = tool.GetUrlArg(addition, "wsHost")
		path = tool.GetUrlArg(addition, "wspath")
	}

	if tool.GetUrlArg(addition, "tls") == "1" {
		tls = "tls"
	} else {
		tls = ""
	}
	aid = tool.GetUrlArg(addition, "aid")
	if aid == "" {
		aid = "0"
	}

	// 构造节点
	proxy := Proxy{}
	proxy.vmessConstruct("vmess_group", remarks, add, port, fakeType, id, aid, net, cipher,
		path, host, "", tls, "", nil, nil, nil, nil)
	return proxy, nil
}

func explodeKitsunebi(kit string) (Proxy, error) {
	var add, port, fakeType, id, path, host, tls, remarks string
	// 其他变量定义
	aid, net, cipher := "0", "tcp", "auto"

	u, err := url.Parse(kit)
	if err != nil {
		return Proxy{}, err
	}

	// 分解主配置和附加参数
	remarks = u.Fragment
	id = u.User.Username()
	add = u.Hostname()
	port = u.Port()
	path = u.Path
	addition := u.RawQuery

	if port == "0" {
		return Proxy{}, errors.New("vmess1 config port is 0")
	}

	// 解析addition
	net = tool.GetUrlArg(addition, "network")
	if tool.GetUrlArg(addition, "tls") == "true" {
		tls = "tls"
	} else {
		tls = ""
	}
	if net == "ws" {
		host = tool.GetUrlArg(addition, "ws.host")
	} else if net == "http" {
		host = tool.GetUrlArg(addition, "http.host")
	} else if net == "quic" {
		host = tool.GetUrlArg(addition, "quic.security")
		path = tool.GetUrlArg(addition, "quic.key")
	}

	if remarks == "" {
		remarks = add + ":" + port
	}

	scv := false
	if tool.GetUrlArg(addition, "tls.allowinsecure") == "true" {
		scv = true
	}

	// 构造节点
	proxy := Proxy{}
	proxy.vmessConstruct("vmess_group", remarks, add, port, fakeType, id, aid, net, cipher,
		path, host, "", tls, "", nil, nil, &scv, nil)
	return proxy, nil

}

// func v2rConf(s string) (ClashVmess, error) {
// 	vmconfig, err := tool.Base64DecodeStripped(s)
// 	if err != nil {
// 		return ClashVmess{}, err
// 	}
// 	vmess := Vmess{}
// 	err = json.Unmarshal(vmconfig, &vmess)
// 	if err != nil {
// 		log.LogError("v2ray config json unmarshal failed, err: %v", err)
// 		return ClashVmess{}, err
// 	}
// 	clashVmess := ClashVmess{}
// 	clashVmess.Name = vmess.PS

// 	clashVmess.Type = "vmess"
// 	clashVmess.UDP = false // 需网络测试是否支持udp
// 	clashVmess.Server = vmess.Add
// 	switch vmess.Port.(type) {
// 	case string:
// 		clashVmess.Port, _ = vmess.Port.(string)
// 	case int:
// 		clashVmess.Port, _ = vmess.Port.(int)
// 	case float64:
// 		clashVmess.Port, _ = vmess.Port.(float64)
// 	default:

// 	}
// 	clashVmess.UUID = vmess.ID
// 	clashVmess.AlterID = vmess.Aid
// 	clashVmess.Cipher = vmess.Type
// 	if strings.EqualFold(vmess.TLS, "tls") {
// 		clashVmess.TLS = true
// 	} else {
// 		clashVmess.TLS = false
// 	}
// 	if vmess.Net == "ws" {
// 		clashVmess.Network = vmess.Net
// 		clashVmess.WSOpts.Path = vmess.Path
// 	}

// 	return clashVmess, nil
// }
