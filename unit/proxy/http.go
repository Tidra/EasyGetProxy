package proxy

import (
	"fmt"
	"net/url"

	"github.com/spf13/cast"
)

// HTTPProxy http 代理结构体
type HTTPProxy struct {
	Group          string                 `json:"group,omitempty"`
	Name           string                 `json:"name,omitempty"`
	OriginName     string                 `json:"-,omitempty"` // 原始名称
	Server         string                 `json:"server,omitempty"`
	Port           int                    `json:"port,omitempty"`
	Username       string                 `json:"username,omitempty"`
	Password       string                 `json:"password,omitempty"`
	TLSSecure      bool                   `json:"tls,omitempty"`
	SkipCertVerify bool                   `json:"skip-cert-verify,omitempty"`
	SNI            string                 `json:"sni,omitempty"`
	Fingerprint    string                 `json:"fingerprint,omitempty"`
	IpVersion      string                 `json:"ip-version,omitempty"`
	Headers        map[string]interface{} `json:"headers,omitempty"`

	Country     string  `json:"country,omitempty"`
	Speed       float64 `json:"speed,omitempty"`
	IsValidFlag bool    `json:"isValidFlag,omitempty"`
}

// GetType 实现 Proxy 接口的 GetType 方法
func (h *HTTPProxy) GetType() string {
	if h.TLSSecure {
		return "https"
	}
	return "http"
}

// GetName 实现 Proxy 接口的 GetName 方法
func (h *HTTPProxy) GetName() string {
	return h.Name
}

// GetOriginName 实现 Proxy 接口的 GetOriginName 方法
func (h *HTTPProxy) GetOriginName() string {
	if h.OriginName != "" {
		return h.OriginName
	} else {
		return h.Name
	}
}

// SetName 实现 Proxy 接口的 SetName 方法
func (h *HTTPProxy) SetName(name string) {
	if h.OriginName == "" {
		h.OriginName = h.Name // 保存原始名称
	}
	h.Name = name
}

// GetCountry 实现 Proxy 接口的 GetCountry 方法
func (h *HTTPProxy) GetCountry() string {
	return h.Country
}

// SetCountry 实现 Proxy 接口的 SetCountry 方法
func (h *HTTPProxy) SetCountry(country string) {
	h.Country = country
}

// GetSpeed 实现 Proxy 接口的 GetSpeed 方法
func (h *HTTPProxy) GetSpeed() float64 {
	return h.Speed
}

// SetSpeed 实现 Proxy 接口的 SetSpeed 方法
func (h *HTTPProxy) SetSpeed(speed float64) {
	h.Speed = speed
}

// IsValid 实现 Proxy 接口的 IsValid 方法
func (h *HTTPProxy) IsValid() bool {
	return h.IsValidFlag
}

// SetIsValid 实现 Proxy 接口的 SetIsValid 方法
func (h *HTTPProxy) SetIsValid(isValid bool) {
	h.IsValidFlag = isValid
}

// GetIdentifier 实现 Proxy 接口的 GetIdentifier 方法
func (h *HTTPProxy) GetIdentifier() string {
	return fmt.Sprintf("%s-%s-%d", h.GetType(), h.Server, h.Port)
}

// ToString 实现 Proxy 接口的 ToString 方法，将 http 代理转换为 http 链接
func (h *HTTPProxy) ToString() string {
	scheme := "http"
	if h.TLSSecure {
		scheme = "https"
	}
	proxyStr := fmt.Sprintf("%s://", scheme)
	if h.Username != "" && h.Password != "" {
		proxyStr += fmt.Sprintf("%s:%s@", h.Username, h.Password)
	}
	proxyStr += fmt.Sprintf("%s:%d", h.Server, h.Port)
	if h.Name != "" {
		proxyStr += "#" + url.QueryEscape(h.Name)
	}
	return proxyStr
}

// explodeHTTP 解析 http 代理链接
func explodeHTTP(httpURL string) (Proxy, error) {
	u, err := url.Parse(httpURL)
	if err != nil {
		return nil, fmt.Errorf("解析 URL 失败: %w", err)
	}

	remarks := u.Fragment
	server := u.Hostname()
	port := u.Port()
	username := ""
	password := ""
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}
	tls := u.Scheme == "https"

	// 构造节点
	proxy := &HTTPProxy{
		Group:      "http_group",
		Name:       remarks,
		OriginName: remarks, // 保存原始名称
		Server:     server,
		Port:       cast.ToInt(port),
		Username:   username,
		Password:   password,
		TLSSecure:  tls,
	}
	return proxy, nil
}
