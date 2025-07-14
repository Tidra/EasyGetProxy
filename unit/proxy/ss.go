package proxy

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/spf13/cast"
)

// SSProxy ss 代理结构体
type SSProxy struct {
	Group             string `json:"group,omitempty"`
	Name              string `json:"name,omitempty"`
	OriginName        string `json:"-,omitempty"` // 原始名称
	Server            string `json:"server,omitempty"`
	Port              int    `json:"port,omitempty"`
	Password          string `json:"password,omitempty"`
	EncryptMethod     string `json:"encryptMethod,omitempty"`
	UDP               bool   `json:"udp,omitempty"`
	UdpOverTCP        bool   `json:"udp-over-tcp,omitempty"`
	UdpOverTCPVersion int    `json:"udp-over-tcp-version,omitempty"`
	IpVersion         string `json:"ip-version,omitempty"`
	Plugin            struct {
		Name   string                 `json:"name,omitempty"`   // 插件名称
		Params map[string]interface{} `json:"params,omitempty"` // 参数键值对
		Raw    string                 `json:"raw,omitempty"`    // 原始插件字符串
	} `json:"plugin,omitempty"`
	Smux struct {
		Enable bool `json:"enable,omitempty"`
	} `json:"smux,omitempty"`
	ClientFingerprint string `json:"client-fingerprint,omitempty"`

	Country     string  `json:"country,omitempty"`
	Speed       float64 `json:"speed,omitempty"`
	IsValidFlag bool    `json:"isValidFlag,omitempty"`
}

// GetType 实现 Proxy 接口的 GetType 方法
func (s *SSProxy) GetType() string {
	return "ss"
}

// GetName 实现 Proxy 接口的 GetName 方法
func (s *SSProxy) GetName() string {
	return s.Name
}

// GetOriginName 实现 Proxy 接口的 GetOriginName 方法，返回代理原始名称
func (s *SSProxy) GetOriginName() string {
	if s.OriginName != "" {
		return s.OriginName
	}
	return s.Name
}

// SetName 实现 Proxy 接口的 SetName 方法，设置代理节点名称
func (s *SSProxy) SetName(name string) {
	if s.OriginName == "" {
		s.OriginName = s.Name // 保存原始名称
	}
	s.Name = name
}

// GetCountry 实现 Proxy 接口的 GetCountry 方法
func (s *SSProxy) GetCountry() string {
	return s.Country
}

// SetCountry 实现 Proxy 接口的 SetCountry 方法
func (s *SSProxy) SetCountry(country string) {
	s.Country = country
}

// GetSpeed 实现 Proxy 接口的 GetSpeed 方法
func (s *SSProxy) GetSpeed() float64 {
	return s.Speed
}

// SetSpeed 实现 Proxy 接口的 SetSpeed 方法
func (s *SSProxy) SetSpeed(speed float64) {
	s.Speed = speed
}

// IsValid 实现 Proxy 接口的 IsValid 方法
func (s *SSProxy) IsValid() bool {
	return s.IsValidFlag
}

// SetIsValid 实现 Proxy 接口的 SetIsValid 方法
func (s *SSProxy) SetIsValid(isValid bool) {
	s.IsValidFlag = isValid
}

// GetIdentifier 实现 Proxy 接口的 GetIdentifier 方法
func (s *SSProxy) GetIdentifier() string {
	return fmt.Sprintf("%s-%s-%d", s.GetType(), s.Server, s.Port)
}

// ToString 实现 Proxy 接口的 ToString 方法，将 ss 代理转换为 ss 链接
func (s *SSProxy) ToString() string {
	proxyStr := "ss://" + tool.Base64EncodeString(s.EncryptMethod+":"+s.Password) + "@" + s.Server + ":" + cast.ToString(s.Port)
	if s.Plugin.Raw != "" {
		proxyStr += "/?plugin=" + s.Plugin.Raw
	}
	if s.Name != "" {
		proxyStr += "#" + url.QueryEscape(s.Name)
	}
	return proxyStr
}

// 实现 ParamProxy 接口的 ToStringWithParam 方法
func (s *SSProxy) ToStringWithParam(param string) string {
	if param == "ssr" {
		// 判断是否符合协议
		if tool.Contains(SsrCiphers, s.EncryptMethod) && s.Plugin.Name == "" {
			baseStr := fmt.Sprintf("%s:%d:origin:%s:plain:%s",
				s.Server,
				s.Port,
				s.EncryptMethod,
				tool.Base64EncodeString(s.Password),
			)

			params := []string{}
			if s.Group != "" {
				params = append(params, fmt.Sprintf("group=%s", tool.Base64EncodeString(s.Group)))
			}
			if s.Name != "" {
				params = append(params, fmt.Sprintf("remarks=%s", tool.Base64EncodeString(s.Name)))
			}

			if len(params) > 0 {
				baseStr += "/?" + strings.Join(params, "&")
			}

			return "ssr://" + tool.Base64EncodeString(baseStr)
		} else {
			return ""
		}
	}
	return s.ToString()
}

// explodeSS 解析 ss 代理链接
func explodeSS(ss string) (Proxy, error) {
	var password, method, server, port, pluginRaw string

	u, err := url.Parse(ss)
	if err != nil {
		return nil, fmt.Errorf("解析 URL 失败: %w", err)
	}

	// 分解主配置和附加参数
	remarks := u.Fragment
	if u.User.String() == "" {
		// base64 的情况
		infos, err := tool.Base64DecodeString(u.Hostname())
		if err != nil {
			return nil, fmt.Errorf("Base64 解码失败: %w", err)
		}
		u, err = url.Parse("ss://" + infos)
		if err != nil {
			return nil, fmt.Errorf("解析 URL 失败: %w", err)
		}
		method = u.User.Username()
		password, _ = u.User.Password()
	} else {
		cipherInfoString, err := tool.Base64DecodeString(u.User.Username())
		if err != nil {
			return nil, fmt.Errorf("Base64 解码失败: %w", err)
		} else if strings.Contains(cipherInfoString, "ss:") {
			cipherInfoString, err = tool.Base64DecodeString(strings.TrimPrefix(cipherInfoString, "ss://"))
			if err != nil {
				return nil, fmt.Errorf("Base64 解码失败: %w", err)
			}
		}
		cipherInfo := strings.SplitN(cipherInfoString, ":", 2)
		if len(cipherInfo) < 2 {
			return nil, errors.New("密码信息格式错误")
		}
		method = strings.ToLower(cipherInfo[0])
		password = cipherInfo[1]
	}
	server = u.Hostname()
	port = u.Port()
	pluginRaw = tool.GetUrlArg(u.RawQuery, "plugin")

	plugin := ""
	pluginOpts := make(map[string]interface{})
	if parts := strings.Split(pluginRaw, ";"); len(parts) > 0 {
		plugin = parts[0]
		for _, kv := range parts[1:] {

			pair := strings.SplitN(kv, "=", 2)
			if len(pair) == 2 {
				pluginOpts[pair[0]] = pair[1]
			} else {
				pluginOpts[pair[0]] = true
			}
		}
	} else {
		plugin = pluginRaw
	}

	// 构造节点
	proxy := &SSProxy{
		Group:         "ss",
		Name:          remarks,
		Server:        server,
		Port:          cast.ToInt(port),
		Password:      password,
		EncryptMethod: method,
		Plugin: struct {
			Name   string                 `json:"name,omitempty"`   // 插件名称
			Params map[string]interface{} `json:"params,omitempty"` // 参数键值对
			Raw    string                 `json:"raw,omitempty"`    // 原始插件字符串
		}{
			Name:   plugin,
			Params: pluginOpts,
			Raw:    pluginRaw,
		},
	}
	return proxy, nil
}
