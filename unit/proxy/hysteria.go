package proxy

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cast"
)

// HysteriaProxy hysteria 代理结构体
type HysteriaProxy struct {
	Group          string   `json:"group,omitempty"`
	Name           string   `json:"name,omitempty"`
	OriginName     string   `json:"-,omitempty"` // 原始名称
	Server         string   `json:"server,omitempty"`
	Port           int      `json:"port,omitempty"`
	Ports          string   `json:"ports,omitempty"`
	Auth           string   `json:"auth,omitempty"`
	ALPN           []string `json:"alpn,omitempty"`
	Obfs           string   `json:"obfs,omitempty"`
	ObfsParam      string   `json:"obfsParam,omitempty"`
	Protocol       string   `json:"protocol,omitempty"`
	Up             string   `json:"upmbps,omitempty"`
	Down           string   `json:"downmbps,omitempty"`
	SNI            string   `json:"sni,omitempty"`
	SkipCertVerify bool     `json:"skip-cert-verify,omitempty"`
	RecvWindowConn int      `json:"recv-window-conn,omitempty"`
	RecvWindow     int      `json:"recv-window,omitempty"`
	Ca             string   `json:"ca,omitempty"`
	CaStr          string   `json:"ca-str,omitempty"`
	DisableMTU     bool     `json:"disable_mtu_discovery,omitempty"`
	Fingerprint    string   `json:"fingerprint,omitempty"`
	FastOpen       bool     `json:"fast-open,omitempty"`

	Country     string  `json:"country,omitempty"`
	Speed       float64 `json:"speed,omitempty"`
	IsValidFlag bool    `json:"is-valid,omitempty"`
}

// GetType 实现 Proxy 接口的 GetType 方法，返回代理类型
func (p *HysteriaProxy) GetType() string {
	return "hysteria"
}

// GetName 实现 Proxy 接口的 GetName 方法，返回代理节点名称
func (p *HysteriaProxy) GetName() string {
	return p.Name
}

// SetName 实现 Proxy 接口的 SetName 方法，设置代理节点名称
func (p *HysteriaProxy) SetName(name string) {
	if p.OriginName == "" {
		p.OriginName = p.Name // 保存原始名称
	}
	p.Name = name
}

// GetOriginName 实现 Proxy 接口的 GetOriginName 方法，返回代理原始名称
func (p *HysteriaProxy) GetOriginName() string {
	if p.OriginName != "" {
		return p.OriginName
	}
	return p.Name
}

// GetCountry 实现 Proxy 接口的 GetCountry 方法，返回代理所属国家
func (p *HysteriaProxy) GetCountry() string {
	return p.Country
}

// SetCountry 实现 Proxy 接口的 SetCountry 方法
func (p *HysteriaProxy) SetCountry(country string) {
	p.Country = country
}

// GetSpeed 实现 Proxy 接口的 GetSpeed 方法，返回代理速度
func (p *HysteriaProxy) GetSpeed() float64 {
	return p.Speed
}

// SetSpeed 实现 Proxy 接口的 SetSpeed 方法
func (p *HysteriaProxy) SetSpeed(speed float64) {
	p.Speed = speed
}

// IsValid 实现 Proxy 接口的 IsValid 方法，判断代理是否有效
func (p *HysteriaProxy) IsValid() bool {
	return p.IsValidFlag
}

// SetIsValid 实现 Proxy 接口的 SetIsValid 方法
func (p *HysteriaProxy) SetIsValid(isValid bool) {
	p.IsValidFlag = isValid
}

// GetIdentifier 实现 Proxy 接口的 GetIdentifier 方法，返回代理唯一标识
func (p *HysteriaProxy) GetIdentifier() string {
	return fmt.Sprintf("%s-%s-%d", p.GetType(), p.Server, p.Port)
}

// ToString 实现 Proxy 接口的 ToString 方法，将代理信息转换为 hysteria 协议链接字符串
func (p *HysteriaProxy) ToString() string {
	baseURL := fmt.Sprintf("hysteria://%s:%d", p.Server, p.Port)
	var params []string

	addParam := func(key, value string) {
		if value != "" {
			params = append(params, fmt.Sprintf("%s=%s", key, value))
		}
	}

	addParam("auth", p.Auth)
	addParam("peer", p.SNI)
	addParam("upmbps", p.Up)
	addParam("downmbps", p.Down)

	if len(p.ALPN) > 0 {
		addParam("alpn", strings.Join(p.ALPN, ","))
	}

	addParam("obfs", p.Obfs)
	addParam("obfsParam", p.ObfsParam)
	addParam("protocol", p.Protocol)

	if p.SkipCertVerify {
		params = append(params, "insecure=1")
	}

	if len(params) > 0 {
		baseURL += "?" + strings.Join(params, "&")
	}

	if p.Name != "" {
		baseURL += "#" + url.QueryEscape(p.Name)
	}

	return baseURL
}

// explodeHysteria 解析 hysteria 代理链接，返回 Proxy 接口实例和可能的错误
func explodeHysteria(proxyStr string) (Proxy, error) {
	u, err := url.Parse(proxyStr)
	if err != nil {
		return nil, fmt.Errorf("解析 URL 失败: %w", err)
	}

	query := u.Query()
	port, err := cast.ToIntE(u.Port())
	if err != nil {
		return nil, fmt.Errorf("端口转换失败: %w", err)
	}

	p := &HysteriaProxy{
		Group:          "hysteria_group",
		Name:           u.Fragment,
		OriginName:     u.Fragment, // 保存原始名称
		Server:         u.Hostname(),
		Port:           port,
		Obfs:           query.Get("obfs"),
		ObfsParam:      query.Get("obfsParam"),
		Protocol:       query.Get("protocol"),
		SkipCertVerify: cast.ToBool(query.Get("insecure")),
	}

	if peer := query.Get("peer"); peer != "" {
		p.SNI = peer
	}
	if up := query.Get("upmbps"); up != "" {
		p.Up = up
	}
	if down := query.Get("downmbps"); down != "" {
		p.Down = down
	}
	if alpn := query.Get("alpn"); alpn != "" {
		p.ALPN = strings.Split(alpn, ",")
	}

	return p, nil
}
