package proxy

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/spf13/cast"
)

// Socks5Proxy socks5 代理结构体
type Socks5Proxy struct {
	Group          string  `json:"group,omitempty"`
	Name           string  `json:"name,omitempty"`
	OriginName     string  `json:"-,omitempty"` // 原始名称
	Server         string  `json:"server,omitempty"`
	Port           int     `json:"port,omitempty"`
	Username       string  `json:"username,omitempty"`
	Password       string  `json:"password,omitempty"`
	UDP            bool    `json:"udp,omitempty"`
	TCPFastOpen    bool    `json:"tfo,omitempty"`
	SkipCertVerify bool    `json:"skipCertVerify,omitempty"`
	Country        string  `json:"country,omitempty"`
	Speed          float64 `json:"speed,omitempty"`
	IsValidFlag    bool    `json:"isValidFlag,omitempty"`
}

// GetType 实现 Proxy 接口的 GetType 方法
func (s *Socks5Proxy) GetType() string {
	return "socks5"
}

// GetName 实现 Proxy 接口的 GetName 方法
func (s *Socks5Proxy) GetName() string {
	return s.Name
}

// SetName 实现 Proxy 接口的 SetName 方法，设置代理节点名称
func (s *Socks5Proxy) SetName(name string) {
	if s.OriginName == "" {
		s.OriginName = s.Name // 保存原始名称
	}
	s.Name = name
}

// GetOriginName 实现 Proxy 接口的 GetOriginName 方法，返回代理原始名称
func (s *Socks5Proxy) GetOriginName() string {
	if s.OriginName != "" {
		return s.OriginName
	}
	return s.Name
}

// GetCountry 实现 Proxy 接口的 GetCountry 方法
func (s *Socks5Proxy) GetCountry() string {
	return s.Country
}

// SetCountry 实现 Proxy 接口的 SetCountry 方法
func (s *Socks5Proxy) SetCountry(country string) {
	s.Country = country
}

// GetSpeed 实现 Proxy 接口的 GetSpeed 方法
func (s *Socks5Proxy) GetSpeed() float64 {
	return s.Speed
}

// SetSpeed 实现 Proxy 接口的 SetSpeed 方法
func (s *Socks5Proxy) SetSpeed(speed float64) {
	s.Speed = speed
}

// IsValid 实现 Proxy 接口的 IsValid 方法
func (s *Socks5Proxy) IsValid() bool {
	return s.IsValidFlag
}

// SetIsValid 实现 Proxy 接口的 SetIsValid 方法
func (s *Socks5Proxy) SetIsValid(isValid bool) {
	s.IsValidFlag = isValid
}

// GetIdentifier 实现 Proxy 接口的 GetIdentifier 方法
func (s *Socks5Proxy) GetIdentifier() string {
	return fmt.Sprintf("%s-%s-%d", s.GetType(), s.Server, s.Port)
}

// ToString 实现 Proxy 接口的 ToString 方法，将 socks5 代理转换为 socks5 链接
func (s *Socks5Proxy) ToString() string {
	proxyStr := "socks5://"
	if s.Username != "" && s.Password != "" {
		proxyStr += fmt.Sprintf("%s:%s@", s.Username, s.Password)
	}
	proxyStr += fmt.Sprintf("%s:%d", s.Server, s.Port)
	if s.Name != "" {
		proxyStr += "#" + url.QueryEscape(s.Name)
	}
	return proxyStr
}

// explodeSocks5 解析 socks5 代理链接
func explodeSocks5(socks5URL string) (Proxy, error) {
	u, err := url.Parse(socks5URL)
	if err != nil {
		return nil, fmt.Errorf("解析 URL 失败: %w", err)
	}

	if u.Scheme != "socks5" {
		return nil, errors.New("不是有效的 socks5 链接")
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

	// 构造节点
	proxy := &Socks5Proxy{
		Group:      "socks5_group",
		Name:       remarks,
		OriginName: remarks, // 保存原始名称
		Server:     server,
		Port:       cast.ToInt(port),
		Username:   username,
		Password:   password,
	}
	return proxy, nil
}
