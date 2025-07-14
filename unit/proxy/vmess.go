package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/spf13/cast"
)

// Vmess 结构体实现 Proxy 接口
type Vmess struct {
	Group               string `json:"group,omitempty"`
	Name                string `json:"name,omitempty"`
	OriginName          string `json:"-,omitempty"` // 原始名称
	Server              string `json:"server,omitempty"`
	Port                int    `json:"port,omitempty"`
	UDP                 bool   `json:"udp,omitempty"`
	UUID                string `json:"uuid,omitempty"`
	AlterID             int    `json:"alterId,omitempty"`
	Type                string `json:"type,omitempty"` // 伪装类型
	Cipher              string `json:"cipher,omitempty"`
	PacketEncoding      string `json:"packet-encoding,omitempty"`
	GlobalPadding       bool   `json:"global-padding,omitempty"`
	AuthenticatedLength bool   `json:"authenticated-length,omitempty"`

	TLSSecure         bool     `json:"tlsSecure,omitempty"`
	ServerName        string   `json:"serverName,omitempty"`
	Host              string   `json:"host,omitempty"`
	Path              string   `json:"path,omitempty"`
	ALPN              []string `json:"alpn,omitempty"`
	Fingerprint       string   `json:"fingerprint,omitempty"`
	ClientFingerprint string   `json:"client-fingerprint,omitempty"`
	SkipCertVerify    bool     `json:"skip-cert-verify,omitempty"`

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
	IsValidFlag bool    `json:"isValidFlag,omitempty"`
}

// GetType 实现 Proxy 接口的 GetType 方法
func (v *Vmess) GetType() string {
	return "vmess"
}

// GetName 实现 Proxy 接口的 GetName 方法
func (v *Vmess) GetName() string {
	return v.Name
}

// SetName 实现 Proxy 接口的 SetName 方法，设置代理节点名称
func (v *Vmess) SetName(name string) {
	if v.OriginName == "" {
		v.OriginName = v.Name // 保存原始名称
	}
	v.Name = name
}

// GetOriginName 实现 Proxy 接口的 GetOriginName 方法，返回代理原始名称
func (v *Vmess) GetOriginName() string {
	if v.OriginName != "" {
		return v.OriginName
	}
	return v.Name
}

// GetCountry 实现 Proxy 接口的 GetCountry 方法
func (v *Vmess) GetCountry() string {
	return v.Country
}

// SetCountry 实现 Proxy 接口的 SetCountry 方法
func (v *Vmess) SetCountry(country string) {
	v.Country = country
}

// GetSpeed 实现 Proxy 接口的 GetSpeed 方法
func (v *Vmess) GetSpeed() float64 {
	return v.Speed
}

// SetSpeed 实现 Proxy 接口的 SetSpeed 方法
func (v *Vmess) SetSpeed(speed float64) {
	v.Speed = speed
}

// IsValid 实现 Proxy 接口的 IsValid 方法
func (v *Vmess) IsValid() bool {
	return v.IsValidFlag
}

// SetIsValid 实现 Proxy 接口的 SetIsValid 方法
func (v *Vmess) SetIsValid(isValid bool) {
	v.IsValidFlag = isValid
}

// GetIdentifier 实现 Proxy 接口的 GetIdentifier 方法
func (v *Vmess) GetIdentifier() string {
	return fmt.Sprintf("%s-%s-%d-%s", v.GetType(), v.Server, v.Port, v.UUID)
}

// ToString 实现 Proxy 接口的 ToString 方法
func (v *Vmess) ToString() string {
	vmessNode := map[string]interface{}{
		"v":    "2",
		"ps":   v.Name,
		"add":  v.Server,
		"port": v.Port,
		"id":   v.UUID,
		"aid":  v.AlterID,
		"scy":  v.Cipher,
		"net": func() string {
			if v.Network == "" {
				return "tcp"
			}
			return v.Network
		}(),
		"type": func() string {
			if v.Type == "" {
				return "none"
			}
			return v.Type
		}(),
		"path": v.Path,
		"host": v.Host,
		"tls": func() string {
			if v.TLSSecure {
				return "tls"
			}
			return ""
		}(),
		"sni":  v.ServerName,
		"alpn": strings.Join(v.ALPN, ","),
		"fp":   v.Fingerprint,
	}

	jsonData, err := json.Marshal(vmessNode)
	if err != nil {
		return ""
	}

	return "vmess://" + tool.Base64EncodeString(string(jsonData))
}

func explodeShadowrocket(vmess string) (Proxy, error) {

	u, err := url.Parse(vmess)
	if err != nil {
		return nil, fmt.Errorf("解析 URL 失败: %w", err)
	}

	// 分解主配置和附加参数
	configStr := u.Host
	addition := u.RawQuery

	configStr, err = tool.Base64DecodeString(configStr)
	if err != nil {
		return nil, fmt.Errorf("Base64 解码失败: %w", err)
	}

	var cipher, id, add, port string
	// 使用正则解析参数
	regex := regexp.MustCompile(`(.*?):(.*?)@(.*?):(.*?)`)
	if regex.MatchString(configStr) {
		result := regex.FindStringSubmatch(configStr)[1:]
		cipher, id, add, port = result[0], result[1], result[2], result[3]
	} else {
		return nil, errors.New("vmess config not match: uuid, add, port")
	}

	if port == "0" {
		return nil, errors.New("vmess config port is 0")
	}

	var net, host, path string
	// 解析 Addition
	remarks := tool.GetUrlArg(addition, "remarks")
	obfs := tool.GetUrlArg(addition, "obfs")

	if obfs == "websocket" {
		net = "ws"
		host = tool.GetUrlArg(addition, "obfsParam")
		path = tool.GetUrlArg(addition, "path")
	} else {
		net = tool.GetUrlArg(addition, "network")
		host = tool.GetUrlArg(addition, "wsHost")
		path = tool.GetUrlArg(addition, "wspath")
	}

	aid := tool.GetUrlArg(addition, "aid")
	if aid == "" {
		aid = "0"
	}

	// 构造节点
	proxy := &Vmess{
		Group:      "vmess_group",
		Name:       remarks,
		OriginName: remarks, // 保存原始名称
		Server:     add,
		Port:       cast.ToInt(port),
		UUID:       id,
		AlterID:    cast.ToInt(aid),
		Cipher:     cipher,
		Network:    net,
		ServerName: host,
		Path:       path,
		TLSSecure:  strings.EqualFold(tool.GetUrlArg(addition, "tls"), "1"),
	}

	switch net {
	case "ws":
		proxy.WSOpts.Path = path
		if host != "" {
			proxy.WSOpts.Headers = make(map[string]interface{})
			proxy.WSOpts.Headers["Host"] = host
		}
	case "http":
		proxy.HttpOpts.Method = "GET"
		if path != "" {
			proxy.HttpOpts.Path = strings.Split(path, ",")
		}
		if host != "" {
			proxy.HttpOpts.Headers = make(map[string]interface{})
			proxy.HttpOpts.Headers["Host"] = host
		}
	case "h2":
		proxy.H2Opts.Path = path
		if host != "" {
			proxy.H2Opts.Host = strings.Split(host, ",")
		}
	case "grpc":
		proxy.GRPCOpts.ServiceName = path
	}
	return proxy, nil
}

func explodeKitsunebi(vmess string) (Proxy, error) {
	u, err := url.Parse(vmess)
	if err != nil {
		return nil, fmt.Errorf("解析 URL 失败: %w", err)
	}

	// 分解主配置和附加参数
	remarks := u.Fragment
	add := u.Hostname()
	port := u.Port()
	path := u.Path
	addition := u.RawQuery

	if port == "0" {
		return nil, errors.New("vmess1 config port is 0")
	}

	// 解析addition
	net := tool.GetUrlArg(addition, "network")

	var host string
	switch net {
	case "ws":
		host = tool.GetUrlArg(addition, "ws.host")
	case "http":
		host = tool.GetUrlArg(addition, "http.host")
	case "quic":
		host = tool.GetUrlArg(addition, "quic.security")
		path = tool.GetUrlArg(addition, "quic.key")
	}

	if remarks == "" {
		remarks = fmt.Sprintf("%s:%s", add, port)
	}

	scv := false
	if tool.GetUrlArg(addition, "tls.allowinsecure") == "true" {
		scv = true
	}

	// 构造节点
	proxy := &Vmess{
		Group:          "vmess_group",
		Name:           remarks,
		OriginName:     remarks, // 保存原始名称
		Server:         add,
		Port:           cast.ToInt(port),
		UUID:           u.User.Username(),
		AlterID:        0,
		Cipher:         "auto",
		Network:        net,
		ServerName:     host,
		Path:           path,
		TLSSecure:      strings.EqualFold(tool.GetUrlArg(addition, "tls"), "true"),
		SkipCertVerify: scv,
	}

	switch net {
	case "ws":
		proxy.WSOpts.Path = path
		if host != "" {
			proxy.WSOpts.Headers = make(map[string]interface{})
			proxy.WSOpts.Headers["Host"] = host
		}
	case "http":
		proxy.HttpOpts.Method = "GET"
		if path != "" {
			proxy.HttpOpts.Path = strings.Split(path, ",")
		}
		if host != "" {
			proxy.HttpOpts.Headers = make(map[string]interface{})
			proxy.HttpOpts.Headers["Host"] = host
		}
	case "h2":
		proxy.H2Opts.Path = path
		if host != "" {
			proxy.H2Opts.Host = strings.Split(host, ",")
		}
	case "grpc":
		proxy.GRPCOpts.ServiceName = path
	}

	return proxy, nil
}

func explodeVmess(vmess string) (Proxy, error) {
	shadowrocketPattern := regexp.MustCompile(`vmess://([A-Za-z0-9-_]+)\?(.*)`)
	kitsunebiPattern := regexp.MustCompile(`vmess1://(.*?)\?(.*)`)

	if shadowrocketPattern.MatchString(vmess) {
		return explodeShadowrocket(vmess)
	} else if kitsunebiPattern.MatchString(vmess) {
		return explodeKitsunebi(vmess)
	}

	// 定义正则表达式
	re := regexp.MustCompile("(vmess|vmess1)://")
	// 使用正则表达式替换并解码
	vmess, err := tool.Base64DecodeString(re.ReplaceAllString(vmess, ""))
	if err != nil {
		return nil, fmt.Errorf("base64 解码失败: %w", err)
	}

	var jsondata map[string]interface{}
	err = json.Unmarshal([]byte(vmess), &jsondata)
	// 判断是否解析出错或者解析结果不是一个对象
	if err != nil || jsondata == nil {
		return nil, errors.New("JSON 解析出错或者不是一个对象")
	}

	ps := tool.SafeAsString(jsondata, "ps")
	port := tool.SafeAsInt(jsondata, "port")
	if port == 0 {
		return nil, errors.New("端口不能为 0 或置空")
	}

	cipher := tool.SafeAsString(jsondata, "scy")
	if cipher == "" {
		cipher = "auto"
	}
	network := tool.SafeAsString(jsondata, "net")
	if network == "" {
		network = "tcp"
	}

	host := tool.SafeAsString(jsondata, "host")
	path := tool.SafeAsString(jsondata, "path")
	// 获取version
	version := tool.SafeAsString(jsondata, "v")
	if version == "" || version == "1" {
		if host != "" {
			vArray := strings.Split(host, ";")
			if len(vArray) == 2 {
				host = vArray[0]
				path = vArray[1]
			}
		}
	}

	alpn := strings.Split(tool.SafeAsString(jsondata, "alpn"), ",")

	// 构造节点
	proxy := &Vmess{
		Group:       "vmess_group",
		Name:        ps,
		OriginName:  ps, // 保存原始名称
		Server:      tool.SafeAsString(jsondata, "add"),
		Port:        port,
		UUID:        tool.SafeAsString(jsondata, "id"),
		AlterID:     tool.SafeAsInt(jsondata, "aid"),
		Type:        tool.SafeAsString(jsondata, "type"),
		Cipher:      cipher,
		Network:     network,
		ServerName:  tool.SafeAsString(jsondata, "sni"),
		Host:        host,
		Path:        path,
		TLSSecure:   tool.SafeAsBool(jsondata, "tls"),
		ALPN:        alpn,
		Fingerprint: tool.SafeAsString(jsondata, "fp"),
	}

	switch network {
	case "ws":
		proxy.WSOpts.Path = path
		proxy.WSOpts.Headers = make(map[string]interface{})
		if host != "" {
			proxy.WSOpts.Headers["Host"] = host
		}
	case "http":
		proxy.HttpOpts.Method = "GET"
		if path != "" {
			proxy.HttpOpts.Path = strings.Split(path, ",")
		}
		if host != "" {
			proxy.HttpOpts.Headers = make(map[string]interface{})
			proxy.HttpOpts.Headers["Host"] = host
		}
	case "h2":
		proxy.H2Opts.Path = path
		if host != "" {
			proxy.H2Opts.Host = strings.Split(host, ",")
		}
	case "grpc":
		proxy.GRPCOpts.ServiceName = path
	}

	return proxy, nil
}
