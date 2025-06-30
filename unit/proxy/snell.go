package proxy

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cast"
)

// SnellProxy snell 代理结构体
type SnellProxy struct {
	Group          string  `json:"group,omitempty"`
	Name           string  `json:"name,omitempty"`
	Server         string  `json:"server,omitempty"`
	Port           int     `json:"port,omitempty"`
	PSK            string  `json:"psk,omitempty"`
	Version        int     `json:"version,omitempty"`
	Obfs           string  `json:"obfs,omitempty"`
	ObfsParam      string  `json:"obfs-param,omitempty"`
	UDP            bool    `json:"udp,omitempty"`
	SkipCertVerify bool    `json:"skip-cert-verify,omitempty"`
	Country        string  `json:"country,omitempty"`
	Speed          float64 `json:"speed,omitempty"`
	IsValidFlag    bool    `json:"is-valid,omitempty"`
	OriginName     string  `json:"-,omitempty"` // 原始名称
}

// GetType 实现 Proxy 接口的 GetType 方法，返回代理类型
func (p *SnellProxy) GetType() string {
	return "snell"
}

// GetName 实现 Proxy 接口的 GetName 方法，返回代理节点名称
func (p *SnellProxy) GetName() string {
	return p.Name
}

// SetName 实现 Proxy 接口的 SetName 方法，设置代理节点名称
func (p *SnellProxy) SetName(name string) {
	p.Name = name
}

// GetOriginName 实现 Proxy 接口的 GetOriginName 方法，返回代理原始名称
func (p *SnellProxy) GetOriginName() string {
	if p.OriginName != "" {
		return p.OriginName
	}
	return p.Name
}

// GetCountry 实现 Proxy 接口的 GetCountry 方法，返回代理所属国家
func (p *SnellProxy) GetCountry() string {
	return p.Country
}

// SetCountry 实现 Proxy 接口的 SetCountry 方法
func (p *SnellProxy) SetCountry(country string) {
	p.Country = country
}

// GetSpeed 实现 Proxy 接口的 GetSpeed 方法，返回代理速度
func (p *SnellProxy) GetSpeed() float64 {
	return p.Speed
}

// SetSpeed 实现 Proxy 接口的 SetSpeed 方法
func (p *SnellProxy) SetSpeed(speed float64) {
	p.Speed = speed
}

// IsValid 实现 Proxy 接口的 IsValid 方法，判断代理是否有效
func (p *SnellProxy) IsValid() bool {
	return p.IsValidFlag
}

// SetIsValid 实现 Proxy 接口的 SetIsValid 方法
func (p *SnellProxy) SetIsValid(isValid bool) {
	p.IsValidFlag = isValid
}

// GetIdentifier 实现 Proxy 接口的 GetIdentifier 方法，返回代理唯一标识
func (p *SnellProxy) GetIdentifier() string {
	return fmt.Sprintf("%s-%s-%d", p.GetType(), p.Server, p.Port)
}

// ToString 实现 Proxy 接口的 ToString 方法，将代理信息转换为 snell 协议链接字符串
func (p *SnellProxy) ToString() string {
	baseURL := fmt.Sprintf("snell://%s@%s:%d", p.PSK, p.Server, p.Port)
	var params []string

	addParam := func(key, value string) {
		if value != "" {
			params = append(params, fmt.Sprintf("%s=%s", key, value))
		}
	}

	addParam("version", cast.ToString(p.Version))
	addParam("obfs", p.Obfs)
	addParam("obfs-param", p.ObfsParam)

	if p.UDP {
		params = append(params, "udp=true")
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

// explodeSnell 解析 snell 代理链接，返回 Proxy 接口实例和可能的错误
func explodeSnell(proxyStr string) (Proxy, error) {
	u, err := url.Parse(proxyStr)
	if err != nil {
		return nil, fmt.Errorf("解析 URL 失败: %w", err)
	}

	query := u.Query()
	port, err := cast.ToIntE(u.Port())
	if err != nil {
		return nil, fmt.Errorf("端口转换失败: %w", err)
	}

	udp := cast.ToBool(query.Get("udp"))
	scv := cast.ToBool(query.Get("insecure"))

	p := &SnellProxy{}
	p.Group = query.Get("group")
	p.Name = u.Fragment
	p.OriginName = u.Fragment
	p.Server = u.Hostname()
	p.Port = port
	p.PSK = u.User.Username()
	p.Version = cast.ToInt(query.Get("version"))
	p.Obfs = query.Get("obfs")
	p.ObfsParam = query.Get("obfs-param")
	p.UDP = udp
	p.SkipCertVerify = scv

	return p, nil
}
