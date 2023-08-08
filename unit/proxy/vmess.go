package proxy

import (
	"encoding/json"
	"errors"
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

func (proxy *Proxy) vmessConstruct(group string, ps string, add string, port any, fakeType string, id string,
	aid any, net string, cipher string, path string, host string, edge string, tls string,
	sni string, udp *bool, tfo *bool, scv *bool, tls13 *bool) {
	proxy.commonConstruct("vmess", group, ps, add, port, udp, tfo, scv, tls13)
	if len(id) == 0 {
		proxy.UUID = "00000000-0000-0000-0000-000000000000"
	} else {
		proxy.UUID = id
	}
	proxy.AlterID = cast.ToUint16(aid)
	proxy.EncryptMethod = cipher
	if len(net) == 0 {
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
		if len(host) == 0 {
			proxy.Host = add
		} else {
			proxy.Host = strings.TrimSpace(host)
		}
		if len(path) == 0 {
			proxy.Path = "/"
		} else {
			proxy.Path = strings.TrimSpace(path)
		}
	}
	proxy.FakeType = fakeType
	proxy.TLSSecure = strings.EqualFold(tls, "tls")
}

func v2rConf(s string) (Proxy, error) {
	vmconfig, err := tool.Base64DecodeStripped(s)
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

	log.LogInfo("%+v", vmess)

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
