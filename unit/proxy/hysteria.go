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
	Server         string   `json:"server,omitempty"`
	Port           int      `json:"port,omitempty"`
	Auth           string   `json:"auth,omitempty"`
	SNI            string   `json:"sni,omitempty"`
	Up             string   `json:"upmbps,omitempty"`
	Down           string   `json:"downmbps,omitempty"`
	ALPN           []string `json:"alpn,omitempty"`
	Obfs           string   `json:"obfs,omitempty"`
	ObfsParam      string   `json:"obfsParam,omitempty"`
	UDP            bool     `json:"udp,omitempty"`
	TLS13          bool     `json:"tls13,omitempty"`
	SkipCertVerify bool     `json:"skip-cert-verify,omitempty"`
	Country        string   `json:"country,omitempty"`
	Speed          float64  `json:"speed,omitempty"`
	IsValidFlag    bool     `json:"is-valid,omitempty"`
	OriginName     string   `json:"-,omitempty"` // 原始名称
}

// hysteriaConstruct 构造 hysteria 代理实例
// 参数说明：
// - group: 代理所属的组名
// - name: 代理节点的名称
// - server: 代理服务器地址
// - port: 代理服务器端口
// - auth: 认证信息
// - obfs: 混淆协议名称
// - obfsParam: 混淆协议参数
// - udp: 是否启用 UDP 支持，使用指针类型，允许传入 nil 表示不设置
// - scv: 是否跳过证书验证，使用指针类型，允许传入 nil 表示不设置
// - tls13: 是否启用 TLS 1.3，使用指针类型，允许传入 nil 表示不设置
func (p *HysteriaProxy) hysteriaConstruct(group, name, server string, port int,
	auth, obfs, obfsParam string, udp, scv, tls13 *bool) {
	p.Group = group
	p.Name = name
	p.OriginName = name
	p.Server = server
	p.Port = port
	p.Auth = auth
	p.Obfs = obfs
	p.ObfsParam = obfsParam

	if udp != nil {
		p.UDP = *udp
	}
	if scv != nil {
		p.SkipCertVerify = *scv
	}
	if tls13 != nil {
		p.TLS13 = *tls13
	}
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

	if p.UDP {
		params = append(params, "protocol=udp")
	}
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

	udp := query.Get("protocol") == "udp"
	scv := cast.ToBool(query.Get("insecure"))
	tls13 := true

	p := &HysteriaProxy{}
	p.hysteriaConstruct(
		query.Get("group"),
		u.Fragment,
		u.Hostname(),
		port,
		query.Get("auth"),
		query.Get("obfs"),
		query.Get("obfsParam"),
		&udp,
		&scv,
		&tls13,
	)

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
