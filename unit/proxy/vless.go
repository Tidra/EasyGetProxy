package proxy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/spf13/cast"
)

// VlessProxy vless 代理结构体
type VlessProxy struct {
	Group          string `json:"group,omitempty"`
	Name           string `json:"name,omitempty"`
	OriginName     string `json:"-,omitempty"` // 原始名称
	Server         string `json:"server,omitempty"`
	Port           int    `json:"port,omitempty"`
	UDP            bool   `json:"udp,omitempty"`
	UUID           string `json:"uuid,omitempty"`
	Flow           string `json:"flow,omitempty"`
	PacketEncoding string `json:"packet-encoding,omitempty"`

	TLSSecure         bool     `json:"tls,omitempty"`
	SNI               string   `json:"sni,omitempty"`
	ALPN              []string `json:"alpn,omitempty"`
	Fingerprint       string   `json:"fingerprint,omitempty"`
	ClientFingerprint string   `json:"client-fingerprint,omitempty"`
	SkipCertVerify    bool     `json:"skip-cert-verify,omitempty"`
	Security          string   `json:"security,omitempty"`
	Host              string   `json:"host,omitempty"`
	XUDP              bool     `json:"xudp,omitempty"`
	Encryption        string   `json:"encryption,omitempty"`

	Network string `json:"network,omitempty"`

	Smux struct {
		Enable bool `json:"enable,omitempty"`
	} `json:"smux,omitempty"`

	RealityOpts struct {
		PublicKey string `json:"public-key,omitempty"`
		ShortID   string `json:"short-id,omitempty"`
	} `json:"reality-opts,omitempty"`

	HttpOpts struct {
		Method  string                 `json:"method,omitempty"`
		Path    []string               `json:"path,omitempty"`
		Headers map[string]interface{} `json:"headers,omitempty"`
	} `json:"http-opts,omitempty"`

	H2Opts struct {
		Host []string `json:"host,omitempty"`
		Path string   `json:"path,omitempty"`
	} `json:"h2-opts,omitempty"`

	WSOpts struct {
		Path                     string                 `json:"path,omitempty"`
		Headers                  map[string]interface{} `json:"headers,omitempty"`
		MaxEarlyData             int                    `json:"max-early-data,omitempty"`
		EarlyDataHeaderName      string                 `json:"early-data-header-name,omitempty"`
		V2rayHttpUpgrade         bool                   `json:"v2ray-http-upgrade,omitempty"`
		V2rayHttpUpgradeFastOpen bool                   `json:"v2ray-http-upgrade-fast-open,omitempty"`
	} `json:"ws-opts,omitempty"`

	GRPCOpts struct {
		ServiceName string `json:"serviceName,omitempty"`
	} `json:"grpc-opts,omitempty"`

	Country     string  `json:"country,omitempty"`
	Speed       float64 `json:"speed,omitempty"`
	IsValidFlag bool    `json:"is-valid,omitempty"`
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
	if p.OriginName == "" {
		p.OriginName = p.Name // 保存原始名称
	}
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
	params.Set("type", p.Network)
	params.Set("fp", p.ClientFingerprint)
	params.Set("pbk", p.RealityOpts.PublicKey)
	params.Set("sid", p.RealityOpts.ShortID)
	params.Set("serviceName", p.GRPCOpts.ServiceName)
	params.Set("encryption", p.Encryption)

	if p.WSOpts.Path != "" {
		params.Set("path", p.WSOpts.Path)
	}
	if host := tool.SafeAsString(p.WSOpts.Headers, "Host"); host != "" {
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
		Network:           query.Get("type"),
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
	}

	switch p.Network {
	case "ws":
		p.WSOpts.Path = query.Get("path")
		if host := query.Get("host"); host != "" {
			p.WSOpts.Headers = map[string]interface{}{
				"Host": host,
			}
		}
		p.WSOpts.MaxEarlyData = cast.ToInt(query.Get("max-early-data"))
		p.WSOpts.EarlyDataHeaderName = query.Get("early-data-header-name")
		p.WSOpts.V2rayHttpUpgrade = cast.ToBool(query.Get("v2ray-http-upgrade"))
		p.WSOpts.V2rayHttpUpgradeFastOpen = cast.ToBool(query.Get("v2ray-http-upgrade-fast-open"))
	case "http":
		p.HttpOpts.Method = query.Get("method")
		p.HttpOpts.Path = strings.Split(query.Get("path"), ",")
		if headers := query.Get("headers"); headers != "" {
			p.HttpOpts.Headers = make(map[string]interface{})
			for _, header := range strings.Split(headers, ",") {
				parts := strings.SplitN(header, ":", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					value := strings.TrimSpace(parts[1])
					p.HttpOpts.Headers[key] = value
				}
			}
		}
	case "grpc":
		p.GRPCOpts.ServiceName = query.Get("serviceName")
	}

	if p.XUDP {
		p.PacketEncoding = "xudp"
	}

	if p.Security == "tls" || p.Security == "reality" {
		p.TLSSecure = true
	}

	if alpn := query.Get("alpn"); alpn != "" {
		p.ALPN = strings.Split(alpn, ",")
	}

	return p, nil
}
