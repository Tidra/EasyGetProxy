package proxy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/spf13/cast"
)

// VlessProxy vless 代理结构体
type VlessProxy struct {
	Group             string   `json:"group,omitempty"`
	Name              string   `json:"name,omitempty"`
	Server            string   `json:"server,omitempty"`
	Port              int      `json:"port,omitempty"`
	UUID              string   `json:"uuid,omitempty"`
	Flow              string   `json:"flow,omitempty"`
	Transport         string   `json:"transport,omitempty"`
	Security          string   `json:"security,omitempty"`
	SNI               string   `json:"sni,omitempty"`
	ALPN              []string `json:"alpn,omitempty"`
	Path              string   `json:"path,omitempty"`
	Host              string   `json:"host,omitempty"`
	UDP               bool     `json:"udp,omitempty"`
	SkipCertVerify    bool     `json:"skip-cert-verify,omitempty"`
	Country           string   `json:"country,omitempty"`
	Speed             float64  `json:"speed,omitempty"`
	IsValidFlag       bool     `json:"is-valid,omitempty"`
	ClientFingerprint string   `json:"client-fingerprint,omitempty"`
	XUDP              bool     `json:"xudp,omitempty"`
	Encryption        string   `json:"encryption,omitempty"`
	OriginName        string   `json:"-,omitempty"` // 原始名称

	RealityOpts struct {
		PublicKey string `json:"public-key,omitempty"`
		ShortID   string `json:"short-id,omitempty"`
	} `json:"reality-opts,omitempty"`

	WSOpts struct {
		Path    string            `json:"path,omitempty"`
		Headers map[string]string `json:"headers,omitempty"`
	} `json:"ws-opts,omitempty"`

	GRPCOpts struct {
		ServiceName string `json:"serviceName,omitempty"`
	} `json:"grpc-opts,omitempty"`
}

// GetType 实现 Proxy 接口的 GetType 方法，返回代理类型
func (p *VlessProxy) GetType() string {
	return "vless"
}

// GetName 实现 Proxy 接口的 GetName 方法，返回代理节点名称
func (p *VlessProxy) GetName() string {
	return p.Name
}

// SetName 实现 Proxy 接口的 SetName 方法，设置代理节点名称
func (p *VlessProxy) SetName(name string) {
	p.Name = name
}

// GetOriginName 实现 Proxy 接口的 GetOriginName 方法，返回代理原始名称
func (p *VlessProxy) GetOriginName() string {
	if p.OriginName != "" {
		return p.OriginName
	}
	return p.Name
}

// GetCountry 实现 Proxy 接口的 GetCountry 方法，返回代理所属国家
func (p *VlessProxy) GetCountry() string {
	return p.Country
}

// SetCountry 实现 Proxy 接口的 SetCountry 方法
func (p *VlessProxy) SetCountry(country string) {
	p.Country = country
}

// GetSpeed 实现 Proxy 接口的 GetSpeed 方法，返回代理速度
func (p *VlessProxy) GetSpeed() float64 {
	return p.Speed
}

// SetSpeed 实现 Proxy 接口的 SetSpeed 方法
func (p *VlessProxy) SetSpeed(speed float64) {
	p.Speed = speed
}

// IsValid 实现 Proxy 接口的 IsValid 方法，判断代理是否有效
func (p *VlessProxy) IsValid() bool {
	return p.IsValidFlag
}

// SetIsValid 实现 Proxy 接口的 SetIsValid 方法
func (p *VlessProxy) SetIsValid(isValid bool) {
	p.IsValidFlag = isValid
}

// GetIdentifier 实现 Proxy 接口的 GetIdentifier 方法，返回代理唯一标识
func (p *VlessProxy) GetIdentifier() string {
	return fmt.Sprintf("%s-%s-%d", p.GetType(), p.Server, p.Port)
}

// ToString 实现 Proxy 接口的 ToString 方法，将代理信息转换为 vless 协议链接字符串

func (p *VlessProxy) ToString() string {
	baseURL := fmt.Sprintf("vless://%s@%s:%d", p.UUID, p.Server, p.Port)
	params := url.Values{}

	params.Set("security", p.Security)
	params.Set("sni", p.SNI)
	params.Set("flow", p.Flow)
	params.Set("type", p.Transport)
	params.Set("fp", p.ClientFingerprint)
	params.Set("pbk", p.RealityOpts.PublicKey)
	params.Set("sid", p.RealityOpts.ShortID)
	params.Set("serviceName", p.GRPCOpts.ServiceName)
	params.Set("encryption", p.Encryption)

	if p.WSOpts.Path != "" {
		params.Set("path", p.WSOpts.Path)
	} else if p.Path != "" {
		params.Set("path", p.Path)
	}
	if host := p.WSOpts.Headers["Host"]; host != "" {
		params.Set("host", host)
	} else if p.Host != "" {
		params.Set("host", p.Host)
	}
	if len(p.ALPN) > 0 {
		params.Set("alpn", strings.Join(p.ALPN, ","))
	}
	if p.UDP {
		params.Set("udp", "true")
	}
	if p.SkipCertVerify {
		params.Set("allowInsecure", "1")
	}
	if p.XUDP {
		params.Set("xudp", "true")
	}
	if len(params) > 0 {
		baseURL += "?" + params.Encode()
	}
	if p.Name != "" {
		baseURL += "#" + url.QueryEscape(p.Name)
	}
	return baseURL
}

func explodeVless(proxyStr string) (Proxy, error) {
	pattern := regexp.MustCompile(`vless://([^@]+)@([^:]+):(\d+)(\?[^#]*)?(#.*)?`)
	matches := pattern.FindStringSubmatch(proxyStr)
	if len(matches) == 0 {
		u, err := url.Parse(proxyStr)
		if err != nil {
			return nil, fmt.Errorf("解析 URL 失败: %w", err)
		}
		u.RawQuery = strings.ReplaceAll(u.RawQuery, " ", "")
		return nil, fmt.Errorf("无法识别的 VLESS 链接格式: %s", u.RawQuery)
	}

	uuid := matches[1]
	host := matches[2]
	port := cast.ToInt(matches[3])
	queryStr := strings.TrimPrefix(matches[4], "?")
	fragment := strings.TrimPrefix(matches[5], "#")

	query, _ := url.ParseQuery(queryStr)

	p := &VlessProxy{
		UUID:              uuid,
		Server:            host,
		Port:              port,
		Name:              fragment,
		OriginName:        fragment, // 保存原始名称
		Flow:              query.Get("flow"),
		Transport:         query.Get("type"),
		Security:          query.Get("security"),
		SNI:               query.Get("sni"),
		ClientFingerprint: query.Get("fp"),
		Encryption:        query.Get("encryption"),
		UDP:               cast.ToBool(query.Get("udp")),
		XUDP:              cast.ToBool(query.Get("xudp")),
		SkipCertVerify:    cast.ToBool(query.Get("allowInsecure")) || cast.ToBool(query.Get("insecure")),
		RealityOpts: struct {
			PublicKey string `json:"public-key,omitempty"`
			ShortID   string `json:"short-id,omitempty"`
		}{
			PublicKey: query.Get("pbk"),
			ShortID:   query.Get("sid"),
		},
		WSOpts: struct {
			Path    string            `json:"path,omitempty"`
			Headers map[string]string `json:"headers,omitempty"`
		}{
			Path: query.Get("path"),
			Headers: map[string]string{
				"Host": query.Get("host"),
			},
		},
		GRPCOpts: struct {
			ServiceName string `json:"serviceName,omitempty"`
		}{
			ServiceName: query.Get("serviceName"),
		},
	}

	if alpn := query.Get("alpn"); alpn != "" {
		p.ALPN = strings.Split(alpn, ",")
	}

	return p, nil
}
