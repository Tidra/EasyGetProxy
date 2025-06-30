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
	Group          string  `json:"group,omitempty"`
	Name           string  `json:"name,omitempty"`
	Server         string  `json:"server,omitempty"`
	Port           int     `json:"port,omitempty"`
	Password       string  `json:"password,omitempty"`
	EncryptMethod  string  `json:"encryptMethod,omitempty"`
	Plugin         string  `json:"plugin,omitempty"`
	PluginOption   string  `json:"pluginOption,omitempty"`
	UDP            bool    `json:"udp,omitempty"`
	TCPFastOpen    bool    `json:"tfo,omitempty"`
	SkipCertVerify bool    `json:"skipCertVerify,omitempty"`
	Country        string  `json:"country,omitempty"`
	Speed          float64 `json:"speed,omitempty"`
	IsValidFlag    bool    `json:"isValidFlag,omitempty"`
	OriginName     string  `json:"-,omitempty"` // 原始名称
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
	if s.Plugin != "" && s.PluginOption != "" {
		proxyStr += "/?plugin=" + url.QueryEscape(s.Plugin+";"+s.PluginOption)
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
		if tool.Contains(SsrCiphers, s.EncryptMethod) && s.Plugin == "" {
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

// ssConstruct 构造 ss 代理
func (s *SSProxy) ssConstruct(group, remarks, server, port, password, method, plugin string,
	pluginopts string) {
	s.Group = group
	s.Name = remarks
	s.OriginName = remarks // 保存原始名称
	s.Server = server
	s.Port = cast.ToInt(port)
	s.Password = password
	s.EncryptMethod = method
	s.Plugin = plugin
	s.PluginOption = pluginopts
}

// explodeSS 解析 ss 代理链接
func explodeSS(ss string) (Proxy, error) {
	var password, method, server, port, plugin, pluginOpts string
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
	plugins := tool.GetUrlArg(u.RawQuery, "plugin")

	if pluginpos := strings.Index(plugins, ";"); pluginpos > 0 {
		plugin = plugins[:pluginpos]
		pluginOpts = plugins[pluginpos+1:]
	} else {
		plugin = plugins
	}

	// 构造节点
	proxy := &SSProxy{}
	proxy.ssConstruct("ss_group", remarks, server, port, password, method, plugin, pluginOpts)
	return proxy, nil
}
