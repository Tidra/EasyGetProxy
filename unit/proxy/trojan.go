package proxy

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/spf13/cast"
)

// TrojanProxy trojan 代理结构体
type TrojanProxy struct {
	Group            string  `json:"group,omitempty"`
	Name             string  `json:"name,omitempty"`
	Server           string  `json:"server,omitempty"`
	Port             int     `json:"port,omitempty"`
	Password         string  `json:"password,omitempty"`
	TransferProtocol string  `json:"network,omitempty"`
	Host             string  `json:"host,omitempty"`
	Path             string  `json:"path,omitempty"`
	TLSSecure        bool    `json:"tls,omitempty"`
	UDP              bool    `json:"udp,omitempty"`
	TCPFastOpen      bool    `json:"tfo,omitempty"`
	SkipCertVerify   bool    `json:"skip-cert-verify,omitempty"`
	TLS13            bool    `json:"tls13,omitempty"`
	Country          string  `json:"country,omitempty"`
	Speed            float64 `json:"speed,omitempty"`
	IsValidFlag      bool    `json:"is-valid,omitempty"`
	OriginName       string  `json:"-,omitempty"` // 原始名称
}

// GetType 实现 Proxy 接口的 GetType 方法
func (t *TrojanProxy) GetType() string {
	return "trojan"
}

// GetName 实现 Proxy 接口的 GetName 方法
func (t *TrojanProxy) GetName() string {
	return t.Name
}

// SetName 实现 Proxy 接口的 SetName 方法，设置代理节点名称
func (t *TrojanProxy) SetName(name string) {
	t.Name = name
}

// GetOriginName 实现 Proxy 接口的 GetOriginName 方法，返回代理原始名称
func (t *TrojanProxy) GetOriginName() string {
	if t.OriginName != "" {
		return t.OriginName
	}
	return t.Name
}

// GetCountry 实现 Proxy 接口的 GetCountry 方法
func (t *TrojanProxy) GetCountry() string {
	return t.Country
}

// SetCountry 实现 Proxy 接口的 SetCountry 方法
func (t *TrojanProxy) SetCountry(country string) {
	t.Country = country
}

// GetSpeed 实现 Proxy 接口的 GetSpeed 方法
func (t *TrojanProxy) GetSpeed() float64 {
	return t.Speed
}

// SetSpeed 实现 Proxy 接口的 SetSpeed 方法
func (t *TrojanProxy) SetSpeed(speed float64) {
	t.Speed = speed
}

// IsValid 实现 Proxy 接口的 IsValid 方法
func (t *TrojanProxy) IsValid() bool {
	return t.IsValidFlag
}

// SetIsValid 实现 Proxy 接口的 SetIsValid 方法
func (t *TrojanProxy) SetIsValid(isValid bool) {
	t.IsValidFlag = isValid
}

// GetIdentifier 实现 Proxy 接口的 GetIdentifier 方法
func (t *TrojanProxy) GetIdentifier() string {
	return fmt.Sprintf("%s-%s-%d", t.GetType(), t.Server, t.Port)
}

// ToString 实现 Proxy 接口的 ToString 方法
func (t *TrojanProxy) ToString() string {
	proxyStr := "trojan://" + t.Password + "@" + t.Server + ":" + cast.ToString(t.Port)
	if t.SkipCertVerify {
		proxyStr += "?allowInsecure=1"
	} else {
		proxyStr += "?allowInsecure=0"
	}
	if t.Host != "" {
		proxyStr += "&sni=" + t.Host
	}
	if t.TransferProtocol == "ws" {
		proxyStr += "&ws=1"
		if t.Path != "" {
			proxyStr += "&wspath=" + url.QueryEscape(t.Path)
		}
	}
	proxyStr += "#" + url.QueryEscape(t.Name)
	return proxyStr
}

// trojanConstruct 构造 trojan 代理
func (t *TrojanProxy) trojanConstruct(group, name, server, port, password, network, host,
	path string, tlsSecure bool, udp, tfo, skipCertVerify *bool) {
	t.Group = group
	t.Name = name
	t.OriginName = name // 保存原始名称
	t.Server = server
	t.Port = cast.ToInt(port)
	t.Password = password
	t.Host = host
	t.TLSSecure = tlsSecure
	if network == "" {
		t.TransferProtocol = "tcp"
	} else {
		t.TransferProtocol = network
	}
	t.Path = path
	if udp != nil {
		t.UDP = *udp
	}
	if tfo != nil {
		t.TCPFastOpen = *tfo
	}
	if skipCertVerify != nil {
		t.SkipCertVerify = *skipCertVerify
	}
}

// explodeTrojan 解析 trojan 代理链接
func explodeTrojan(trojan string) (Proxy, error) {
	var server, port, psk, addition, remark, host, path, network string
	var tfo, scv bool

	u, err := url.Parse(trojan)
	if err != nil {
		return nil, err
	}

	// 分解主配置和附加参数
	remark = u.Fragment
	psk = u.User.String()
	server = u.Hostname()
	port = u.Port()
	if port == "0" || port == "" {
		return nil, errors.New("trojan config port is 0")
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
	proxy := &TrojanProxy{}
	proxy.trojanConstruct("trojan_group", remark, server, port, psk, network, host, path, true, nil, &tfo, &scv)
	return proxy, nil
}
