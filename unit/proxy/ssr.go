package proxy

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/spf13/cast"
)

// SSRProxy ssr 代理结构体
type SSRProxy struct {
	Group          string  `json:"group,omitempty"`
	Name           string  `json:"name,omitempty"`
	Server         string  `json:"server,omitempty"`
	Port           int     `json:"port,omitempty"`
	Password       string  `json:"password,omitempty"`
	EncryptMethod  string  `json:"cipher,omitempty"`
	Protocol       string  `json:"protocol,omitempty"`
	ProtocolParam  string  `json:"protocol-param,omitempty"`
	OBFS           string  `json:"obfs,omitempty"`
	OBFSParam      string  `json:"obfs-param,omitempty"`
	UDP            bool    `json:"udp,omitempty"`
	TCPFastOpen    bool    `json:"tfo,omitempty"`
	SkipCertVerify bool    `json:"skip-cert-verify,omitempty"`
	Country        string  `json:"country,omitempty"`
	Speed          float64 `json:"speed,omitempty"`
	IsValidFlag    bool    `json:"is-valid,omitempty"`
	OriginName     string  `json:"-,omitempty"` // 原始名称
}

// GetType 实现 Proxy 接口的 GetType 方法
func (s *SSRProxy) GetType() string {
	return "ssr"
}

// GetName 实现 Proxy 接口的 GetName 方法
func (s *SSRProxy) GetName() string {
	return s.Name
}

// SetName 实现 Proxy 接口的 SetName 方法，设置代理节点名称
func (s *SSRProxy) SetName(name string) {
	s.Name = name
}

// GetOriginName 实现 Proxy 接口的 GetOriginName 方法，返回代理原始名称
func (s *SSRProxy) GetOriginName() string {
	if s.OriginName != "" {
		return s.OriginName
	}
	return s.Name
}

// GetCountry 实现 Proxy 接口的 GetCountry 方法
func (s *SSRProxy) GetCountry() string {
	return s.Country
}

// SetCountry 实现 Proxy 接口的 SetCountry 方法
func (s *SSRProxy) SetCountry(country string) {
	s.Country = country
}

// GetSpeed 实现 Proxy 接口的 GetSpeed 方法
func (s *SSRProxy) GetSpeed() float64 {
	return s.Speed
}

// SetSpeed 实现 Proxy 接口的 SetSpeed 方法
func (s *SSRProxy) SetSpeed(speed float64) {
	s.Speed = speed
}

// IsValid 实现 Proxy 接口的 IsValid 方法
func (s *SSRProxy) IsValid() bool {
	return s.IsValidFlag
}

// SetIsValid 实现 Proxy 接口的 SetIsValid 方法
func (s *SSRProxy) SetIsValid(isValid bool) {
	s.IsValidFlag = isValid
}

// GetIdentifier 实现 Proxy 接口的 GetIdentifier 方法
func (s *SSRProxy) GetIdentifier() string {
	return fmt.Sprintf("%s-%s-%d", s.GetType(), s.Server, s.Port)
}

// ToString 实现 Proxy 接口的 ToString 方法，将 SSR 代理转换为 SSR 链接
func (s *SSRProxy) ToString() string {
	baseStr := fmt.Sprintf("%s:%d:%s:%s:%s:%s",
		s.Server,
		s.Port,
		s.Protocol,
		s.EncryptMethod,
		s.OBFS,
		tool.Base64EncodeString(s.Password),
	)

	params := []string{}
	if s.Group != "" {
		params = append(params, fmt.Sprintf("group=%s", tool.Base64EncodeString(s.Group)))
	}
	if s.Name != "" {
		params = append(params, fmt.Sprintf("remarks=%s", tool.Base64EncodeString(s.Name)))
	}
	if s.OBFSParam != "" {
		params = append(params, fmt.Sprintf("obfsparam=%s", tool.Base64EncodeString(s.OBFSParam)))
	}
	if s.ProtocolParam != "" {
		params = append(params, fmt.Sprintf("protoparam=%s", tool.Base64EncodeString(s.ProtocolParam)))
	}

	if len(params) > 0 {
		baseStr += "/?" + strings.Join(params, "&")
	}

	return "ssr://" + tool.Base64EncodeString(baseStr)
}

// 实现 ParamProxy 接口的 ToStringWithParam 方法
func (s *SSRProxy) ToStringWithParam(param string) string {
	if param == "ss" {
		// 判断是否符合协议
		if tool.Contains(SsCiphers, s.EncryptMethod) && (s.OBFS == "" || s.OBFS == "plain") && (s.Protocol == "" || s.Protocol == "origin") {
			proxyStr := "ss://" + tool.Base64EncodeString(s.EncryptMethod+":"+s.Password) + "@" + s.Server + ":" + cast.ToString(s.Port) + "#"
			if s.Name != "" {
				proxyStr += "#" + url.QueryEscape(s.Name)
			}
			return proxyStr
		} else {
			return ""
		}
	} else {
		return s.ToString()
	}
}

// ssrConstruct 构造 ssr 代理
func (s *SSRProxy) ssrConstruct(group, name, server, port, protocol, method,
	obfs, password, obfsparam, protoparam string, udp *bool) {
	s.Group = group
	s.Name = name
	s.OriginName = name // 保存原始名称
	s.Server = server
	s.Port = cast.ToInt(port)
	s.Password = password
	s.EncryptMethod = method
	s.Protocol = protocol
	s.ProtocolParam = protoparam
	s.OBFS = obfs
	s.OBFSParam = obfsparam
	if udp != nil {
		s.UDP = *udp
	}
}

// explodeSSR 解析 ssr 代理链接
func explodeSSR(ssr string) (Proxy, error) {
	var remarks, group, server, port, method, password, protocol, protoparam, obfs, obfsparam string
	var udp bool

	if !strings.HasPrefix(ssr, "ssr://") {
		return nil, errors.New("不是有效的 ssr 链接")
	}

	ssr, err := tool.Base64DecodeString(ssr[6:])
	if err != nil {
		return nil, fmt.Errorf("Base64 解码失败: %w", err)
	}

	var paramStr string
	if strings.Contains(ssr, "/?") {
		paramStr = ssr[strings.Index(ssr, "/?")+2:]
		ssr = ssr[:strings.Index(ssr, "/?")]

		group, err = tool.Base64DecodeString(tool.GetUrlArg(paramStr, "group"))
		if err != nil {
			return nil, fmt.Errorf("解析 group 参数失败: %w", err)
		}
		remarks, err = tool.Base64DecodeString(tool.GetUrlArg(paramStr, "remarks"))
		if err != nil {
			return nil, fmt.Errorf("解析 remarks 参数失败: %w", err)
		}
		obfsparam, err = tool.Base64DecodeString(tool.GetUrlArg(paramStr, "obfsparam"))
		if err != nil {
			return nil, fmt.Errorf("解析 obfsparam 参数失败: %w", err)
		}
		protoparam, err = tool.Base64DecodeString(tool.GetUrlArg(paramStr, "protoparam"))
		if err != nil {
			return nil, fmt.Errorf("解析 protoparam 参数失败: %w", err)
		}
	}

	// 正则解析
	regex := regexp.MustCompile(`(.+):(.+):(.+):(.+):(.+):(.+)`)
	if regex.MatchString(ssr) {
		result := regex.FindStringSubmatch(ssr)
		server, port, protocol, method, obfs, password = result[1], result[2], result[3], result[4], result[5], result[6]
	} else {
		return nil, errors.New("ssr 配置格式不匹配")
	}

	password, err = tool.Base64DecodeString(password)
	if err != nil {
		return nil, fmt.Errorf("密码 Base64 解码失败: %w", err)
	}
	if port == "0" {
		return nil, errors.New("ssr 端口不能为 0")
	}
	if group == "" {
		group = "ssr_group"
	}
	if remarks == "" {
		remarks = server + ":" + port
	}

	// 根据 obfs 类型设置 UDP
	switch obfs {
	case "tls1.2_ticket_auth",
		"tls1.2_ticket_auth_compatible",
		"tls1.2_ticket_fastauth",
		"tls1.2_ticket_fastauth_compatible":
		udp = true
	}

	// 构造节点
	proxy := &SSRProxy{}
	proxy.ssrConstruct(group, remarks, server, port, protocol, method, obfs, password, obfsparam, protoparam, &udp)
	return proxy, nil
}
