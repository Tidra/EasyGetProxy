package proxy

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/spf13/cast"
)

type Vmess struct {
	Add  string `json:"add"`
	Aid  any    `json:"aid"`
	Host string `json:"host"`
	ID   string `json:"id"`
	Net  string `json:"net"`
	Path string `json:"path"`
	Port any    `json:"port"`
	PS   string `json:"ps"`
	TLS  string `json:"tls"`
	Type string `json:"type"`
	Sni  string `json:"sni"`
	V    any    `json:"v"`
}

func (proxy *Proxy) vmessConstruct(group, ps, add string, port any, fakeType, id string,
	aid any, net, cipher, path, host, edge, tls, sni string, udp, tfo, scv, tls13 *bool) {
	proxy.commonConstruct("vmess", group, ps, add, port, udp, tfo, scv, tls13)
	if id == "" {
		proxy.UUID = "00000000-0000-0000-0000-000000000000"
	} else {
		proxy.UUID = id
	}
	proxy.AlterID = cast.ToInt(aid)
	proxy.EncryptMethod = cipher
	if net == "" {
		proxy.TransferProtocol = "tcp"
	} else {
		proxy.TransferProtocol = net
	}
	proxy.Edge = edge
	proxy.ServerName = sni

	if strings.EqualFold(net, "quic") {
		proxy.QUICSecure = host
		proxy.QUICSecret = path
	} else {
		if host == "" {
			proxy.Host = add
		} else {
			proxy.Host = strings.TrimSpace(host)
		}
		if path == "" {
			proxy.Path = "/"
		} else {
			proxy.Path = strings.TrimSpace(path)
		}
	}
	proxy.FakeType = fakeType
	proxy.TLSSecure = strings.EqualFold(tls, "tls")
}

func explodeShadowrocket(vmess string) (Proxy, error) {
	var add, port, fakeType, id, aid, net, path, host, tls, cipher, remarks string

	u, err := url.Parse(vmess)
	if err != nil {
		return Proxy{}, err
	}

	// 分解主配置和附加参数
	configStr := u.Host
	addition := u.RawQuery

	configStr, err = tool.Base64DecodeString(configStr)
	if err != nil {
		return Proxy{}, err
	}

	// 使用正则解析参数
	regex := regexp.MustCompile(`(.*?):(.*?)@(.*?):(.*?)`)
	if regex.MatchString(configStr) {
		result := regex.FindStringSubmatch(configStr)[1:]
		cipher, id, add, port = result[0], result[1], result[2], result[3]
	} else {
		return Proxy{}, errors.New("vmess config not match: uuid, add, port")
	}

	if port == "0" {
		return Proxy{}, errors.New("vmess config port is 0")
	}

	// 解析 Addition
	remarks = url.QueryEscape(tool.GetUrlArg(addition, "remarks"))
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
	proxy := Proxy{}
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
		return Proxy{}, err
	}

	// 分解主配置和附加参数
	remarks = u.Fragment
	id = u.User.Username()
	add = u.Hostname()
	port = u.Port()
	path = u.Path
	addition := u.RawQuery

	if port == "0" {
		return Proxy{}, errors.New("vmess1 config port is 0")
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
		remarks = add + ":" + port
	}

	scv := false
	if tool.GetUrlArg(addition, "tls.allowinsecure") == "true" {
		scv = true
	}

	// 构造节点
	proxy := Proxy{}
	proxy.vmessConstruct("vmess_group", remarks, add, port, fakeType, id, aid, net, cipher,
		path, host, "", tls, "", nil, nil, &scv, nil)
	return proxy, nil

}

func explodeVmess(vmess string) (Proxy, error) {
	shadowrocketPattern := regexp.MustCompile(`vmess://([A-Za-z0-9-_]+)\?(.*)`)
	// stdVMessPattern := regexp.MustCompile(`vmess://(.*?)@(.*)`)
	kitsunebiPattern := regexp.MustCompile(`vmess1://(.*?)\?(.*)`)

	if shadowrocketPattern.MatchString(vmess) {
		return explodeShadowrocket(vmess)
		// } else if stdVMessPattern.MatchString(vmess) {
		// 	return		explodeStdVMess(vmess)
	} else if kitsunebiPattern.MatchString(vmess) {
		return explodeKitsunebi(vmess)
	}

	// 定义正则表达式
	re := regexp.MustCompile("(vmess|vmess1)://")
	// 使用正则表达式替换并解码
	vmess, err := tool.Base64DecodeString(re.ReplaceAllString(vmess, ""))
	if err != nil {
		return Proxy{}, errors.New("base64解码失败")
	}
	// log.LogInfo(vmess)

	var version, ps, add, port, fakeType, id, aid, net, path, host, tls, sni string
	var jsondata map[string]interface{}
	err = json.Unmarshal([]byte(vmess), &jsondata)
	// 判断是否解析出错或者解析结果不是一个对象
	if err != nil || jsondata == nil {
		return Proxy{}, errors.New("JSON解析出错或者不是一个对象")
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
		return Proxy{}, errors.New("端口不能为0或置空")
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
	proxy := Proxy{}
	proxy.vmessConstruct("vmess_group", ps, add, port, fakeType, id, aid, net, "auto",
		path, host, "", tls, sni, nil, nil, nil, nil)
	return proxy, nil
}

func ProxieToVmess(node Proxy) string {
	if node.Type != "vmess" {
		return ""
	}

	vmessNode := map[string]interface{}{
		"v":    "2",
		"ps":   node.Name,
		"add":  node.Server,
		"port": node.Port,
		"type": func() string {
			if node.FakeType == "" {
				return "none"
			}
			return node.FakeType
		}(),
		"id":  node.UUID,
		"aid": node.AlterID,
		"net": func() string {
			if node.TransferProtocol == "" {
				return "tcp"
			}
			return node.TransferProtocol
		}(),
		"path": node.Path,
		"host": node.Host,
		"tls": func() string {
			if node.TLSSecure {
				return "tls"
			}
			return ""
		}(),
	}

	jsonData, err := json.Marshal(vmessNode)
	if err != nil {
		return ""
	}

	proxyStr := "vmess://" + tool.Base64EncodeString(string(jsonData))
	return proxyStr
}

func VmessToString(proxyList ProxyList) string {
	var vmessStrings strings.Builder
	for _, node := range proxyList {
		if nodeStr := ProxieToVmess(node); nodeStr != "" {
			vmessStrings.WriteString(nodeStr + "\n")
		}
	}

	return tool.Base64EncodeString(vmessStrings.String())
}
