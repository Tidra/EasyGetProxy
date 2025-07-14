package proxy

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cast"
)

// Hy2Proxy hysteria 2 代理结构体
type Hy2Proxy struct {
	Group        string   `json:"group,omitempty"`
	Name         string   `json:"name,omitempty"`
	OriginName   string   `json:"-,omitempty"` // 原始名称
	Server       string   `json:"server,omitempty"`
	Port         int      `json:"port,omitempty"`
	Ports        string   `json:"ports,omitempty"` // 备用端口列表
	Auth         string   `json:"auth,omitempty"`
	Up           string   `json:"up,omitempty"`   // 上行速度
	Down         string   `json:"down,omitempty"` // 下行速度
	Obfs         string   `json:"obfs,omitempty"`
	ObfsPassword string   `json:"obfs-password,omitempty"`
	SNI          string   `json:"sni,omitempty"`
	Insecure     bool     `json:"insecure,omitempty"`
	PinSHA256    string   `json:"pinSHA256,omitempty"`
	Fingerprint  string   `json:"fingerprint,omitempty"` // 客户端指纹
	ALPN         []string `json:"alpn,omitempty"`        // ALPN 列表
	Ca           string   `json:"ca,omitempty"`          // CA 证书
	CaStr        string   `json:"ca-str,omitempty"`      // CA 证书字符串
	Country      string   `json:"country,omitempty"`
	Speed        float64  `json:"speed,omitempty"`
	IsValidFlag  bool     `json:"is-valid,omitempty"`
}

// GetType 实现 Proxy 接口的 GetType 方法，返回代理类型
func (p *Hy2Proxy) GetType() string {
	return "hysteria2"
}

// GetName 实现 Proxy 接口的 GetName 方法，返回代理节点名称
func (p *Hy2Proxy) GetName() string {
	return p.Name
}

// SetName 实现 Proxy 接口的 SetName 方法，设置代理节点名称
func (p *Hy2Proxy) SetName(name string) {
	if p.OriginName == "" {
		p.OriginName = p.Name // 保存原始名称
	}
	p.Name = name
}

// GetOriginName 实现 Proxy 接口的 GetOriginName 方法，返回代理原始名称
func (p *Hy2Proxy) GetOriginName() string {
	if p.OriginName != "" {
		return p.OriginName
	}
	return p.Name
}

// GetCountry 实现 Proxy 接口的 GetCountry 方法，返回代理所属国家
func (p *Hy2Proxy) GetCountry() string {
	return p.Country
}

// SetCountry 实现 Proxy 接口的 SetCountry 方法
func (p *Hy2Proxy) SetCountry(country string) {
	p.Country = country
}

// GetSpeed 实现 Proxy 接口的 GetSpeed 方法，返回代理速度
func (p *Hy2Proxy) GetSpeed() float64 {
	return p.Speed
}

// SetSpeed 实现 Proxy 接口的 SetSpeed 方法
func (p *Hy2Proxy) SetSpeed(speed float64) {
	p.Speed = speed
}

// IsValid 实现 Proxy 接口的 IsValid 方法，判断代理是否有效
func (p *Hy2Proxy) IsValid() bool {
	return p.IsValidFlag
}

// SetIsValid 实现 Proxy 接口的 SetIsValid 方法
func (p *Hy2Proxy) SetIsValid(isValid bool) {
	p.IsValidFlag = isValid
}

// GetIdentifier 实现 Proxy 接口的 GetIdentifier 方法，返回代理唯一标识
func (p *Hy2Proxy) GetIdentifier() string {
	return fmt.Sprintf("%s-%s-%d", p.GetType(), p.Server, p.Port)
}

// ToString 实现 Proxy 接口的 ToString 方法，将代理信息转换为 hy2 协议链接字符串
func (p *Hy2Proxy) ToString() string {
	authPart := ""
	if p.Auth != "" {
		authPart = url.QueryEscape(p.Auth) + "@"
	}
	portPart := ""
	if p.Port != 443 {
		portPart = fmt.Sprintf(":%d", p.Port)
	}
	baseURL := fmt.Sprintf("hy2://%s%s%s", authPart, p.Server, portPart)
	var params []string

	addParam := func(key, value string) {
		if value != "" {
			params = append(params, fmt.Sprintf("%s=%s", key, value))
		}
	}

	addParam("obfs", p.Obfs)
	addParam("obfs-password", p.ObfsPassword)
	addParam("sni", p.SNI)
	addParam("pinSHA256", p.PinSHA256)

	if p.Insecure {
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

// explodeHy2 解析 hy2 代理链接，返回 Proxy 接口实例和可能的错误
func explodeHy2(proxyStr string) (Proxy, error) {
	u, err := url.Parse(proxyStr)
	if err != nil {
		return nil, fmt.Errorf("解析 URL 失败: %w", err)
	}

	query := u.Query()
	port := 443
	if u.Port() != "" {
		port, err = cast.ToIntE(u.Port())
		if err != nil {
			return nil, fmt.Errorf("端口转换失败: %w", err)
		}
	}

	p := &Hy2Proxy{
		Group:        query.Get("group"),
		Name:         u.Fragment,
		OriginName:   u.Fragment,
		Server:       u.Hostname(),
		Port:         port,
		Auth:         u.User.Username(),
		Obfs:         query.Get("obfs"),
		ObfsPassword: query.Get("obfs-password"),
		SNI:          query.Get("sni"),
		Insecure:     cast.ToBool(query.Get("insecure")),
		PinSHA256:    query.Get("pinSHA256"),
	}

	return p, nil
}
