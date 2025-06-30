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
	Group            string  `json:"group,omitempty"`
	Name             string  `json:"name,omitempty"`
	Server           string  `json:"server,omitempty"`
	Port             int     `json:"port,omitempty"`
	UUID             string  `json:"uuid,omitempty"`
	AlterID          int     `json:"alterId,omitempty"`
	EncryptMethod    string  `json:"encryptMethod,omitempty"`
	TransferProtocol string  `json:"transferProtocol,omitempty"`
	Edge             string  `json:"edge,omitempty"`
	ServerName       string  `json:"serverName,omitempty"`
	Host             string  `json:"host,omitempty"`
	Path             string  `json:"path,omitempty"`
	QUICSecure       string  `json:"quicSecure,omitempty"`
	QUICSecret       string  `json:"quicSecret,omitempty"`
	FakeType         string  `json:"fakeType,omitempty"`
	TLSSecure        bool    `json:"tlsSecure,omitempty"`
	UDP              bool    `json:"udp,omitempty"`
	TCPFastOpen      bool    `json:"tfo,omitempty"`
	SkipCertVerify   bool    `json:"skipCertVerify,omitempty"`
	TLS13            bool    `json:"tls13,omitempty"`
	Country          string  `json:"country,omitempty"`
	Speed            float64 `json:"speed,omitempty"`
	IsValidFlag      bool    `json:"isValidFlag,omitempty"`
	OriginName       string  `json:"-,omitempty"` // 原始名称
}

// vmessConstruct 构造 vmess 代理
func (v *Vmess) vmessConstruct(group, ps, add string, port any, fakeType, id string,
	aid any, net, cipher, path, host, edge, tls, sni string, udp, tfo, scv, tls13 *bool) {
	v.Group = group
	v.Name = ps
	v.OriginName = ps // 保存原始名称
	v.Server = add
	v.Port = cast.ToInt(port)
	if id == "" {
		v.UUID = "00000000-0000-0000-0000-000000000000"
	} else {
		v.UUID = id
	}
	v.AlterID = cast.ToInt(aid)
	v.EncryptMethod = cipher
	if net == "" {
		v.TransferProtocol = "tcp"
	} else {
		v.TransferProtocol = net
	}
	v.Edge = edge
	v.ServerName = sni

	if strings.EqualFold(net, "quic") {
		v.QUICSecure = host
		v.QUICSecret = path
	} else {
		if host == "" {
			v.Host = add
		} else {
			v.Host = strings.TrimSpace(host)
		}
		if path == "" {
			v.Path = "/"
		} else {
			v.Path = strings.TrimSpace(path)
		}
	}
	v.FakeType = fakeType
	v.TLSSecure = strings.EqualFold(tls, "tls")

	if udp != nil {
		v.UDP = *udp
	}
	if tfo != nil {
		v.TCPFastOpen = *tfo
	}
	if scv != nil {
		v.SkipCertVerify = *scv
	}
	if tls13 != nil {
		v.TLS13 = *tls13
	}
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
	return fmt.Sprintf("%s-%s-%d", v.GetType(), v.Server, v.Port)
}

// ToString 实现 Proxy 接口的 ToString 方法
func (v *Vmess) ToString() string {
	vmessNode := map[string]interface{}{
		"v":    "2",
		"ps":   v.Name,
		"add":  v.Server,
		"port": v.Port,
		"type": func() string {
			if v.FakeType == "" {
				return "none"
			}
			return v.FakeType
		}(),
		"id":  v.UUID,
		"aid": v.AlterID,
		"net": func() string {
			if v.TransferProtocol == "" {
				return "tcp"
			}
			return v.TransferProtocol
		}(),
		"path": v.Path,
		"host": v.Host,
		"tls": func() string {
			if v.TLSSecure {
				return "tls"
			}
			return ""
		}(),
	}

	jsonData, err := json.Marshal(vmessNode)
	if err != nil {
		return ""
	}

	return "vmess://" + tool.Base64EncodeString(string(jsonData))
}

func explodeShadowrocket(vmess string) (Proxy, error) {
	var add, port, fakeType, id, aid, net, path, host, tls, cipher, remarks string

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

	// 解析 Addition
	remarks = tool.GetUrlArg(addition, "remarks")
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

	if tool.GetUrlArg(addition, "tls") == "1" {
		tls = "tls"
	} else {
		tls = ""
	}
	aid = tool.GetUrlArg(addition, "aid")
	if aid == "" {
		aid = "0"
	}

	// 构造节点
	proxy := &Vmess{}
	proxy.vmessConstruct("vmess_group", remarks, add, port, fakeType, id, aid, net, cipher,
		path, host, "", tls, "", nil, nil, nil, nil)
	return proxy, nil
}

func explodeKitsunebi(vmess string) (Proxy, error) {
	var add, port, fakeType, id, path, host, tls, remarks string
	// 其他变量定义
	aid, net, cipher := "0", "tcp", "auto"

	u, err := url.Parse(vmess)
	if err != nil {
		return nil, fmt.Errorf("解析 URL 失败: %w", err)
	}

	// 分解主配置和附加参数
	remarks = u.Fragment
	id = u.User.Username()
	add = u.Hostname()
	port = u.Port()
	path = u.Path
	addition := u.RawQuery

	if port == "0" {
		return nil, errors.New("vmess1 config port is 0")
	}

	// 解析addition
	net = tool.GetUrlArg(addition, "network")
	if tool.GetUrlArg(addition, "tls") == "true" {
		tls = "tls"
	} else {
		tls = ""
	}
	if net == "ws" {
		host = tool.GetUrlArg(addition, "ws.host")
	} else if net == "http" {
		host = tool.GetUrlArg(addition, "http.host")
	} else if net == "quic" {
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
	proxy := &Vmess{}
	proxy.vmessConstruct("vmess_group", remarks, add, port, fakeType, id, aid, net, cipher,
		path, host, "", tls, "", nil, nil, &scv, nil)
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

	var version, ps, add, port, fakeType, id, aid, net, path, host, tls, sni string
	var jsondata map[string]interface{}
	err = json.Unmarshal([]byte(vmess), &jsondata)
	// 判断是否解析出错或者解析结果不是一个对象
	if err != nil || jsondata == nil {
		return nil, errors.New("JSON 解析出错或者不是一个对象")
	}

	// 获取version
	version = tool.SafeAsString(jsondata, "v")
	if version == "" {
		version = "1"
	}
	ps = tool.SafeAsString(jsondata, "ps")
	add = tool.SafeAsString(jsondata, "add")
	port = tool.SafeAsString(jsondata, "port")
	if port == "0" || port == "" {
		return nil, errors.New("端口不能为 0 或置空")
	}
	fakeType = tool.SafeAsString(jsondata, "type")
	id = tool.SafeAsString(jsondata, "id")
	aid = tool.SafeAsString(jsondata, "aid")
	net = tool.SafeAsString(jsondata, "net")
	tls = tool.SafeAsString(jsondata, "tls")

	host = tool.SafeAsString(jsondata, "host")
	sni = tool.SafeAsString(jsondata, "sni")
	switch version {
	case "1":
		if host != "" {
			vArray := strings.Split(host, ";")
			if len(vArray) == 2 {
				host = vArray[0]
				path = vArray[1]
			}
		}
	case "2":
		path = tool.SafeAsString(jsondata, "path")
	}

	// 构造节点
	proxy := &Vmess{}
	proxy.vmessConstruct("vmess_group", ps, add, port, fakeType, id, aid, net, "auto",
		path, host, "", tls, sni, nil, nil, nil, nil)
	return proxy, nil
}
