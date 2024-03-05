package proxy

import (
	"errors"
	"regexp"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/spf13/cast"
)

func (proxy *Proxy) ssrConstruct(group, remarks, server, port, protocol, method,
	obfs, password, obfsparam, protoparam string, udp, tfo, scv *bool) {
	proxy.commonConstruct("ssr", group, remarks, server, port, udp, tfo, scv, nil)
	proxy.Password = password
	proxy.EncryptMethod = method
	proxy.Protocol = protocol
	proxy.ProtocolParam = protoparam
	proxy.OBFS = obfs
	proxy.OBFSParam = obfsparam
}

func explodeSSR(ssr string) (Proxy, error) {
	var remarks, group, server, port, method, password, protocol, protoparam, obfs, obfsparam string
	var udp bool

	ssr, err := tool.Base64DecodeString(ssr[6:])
	if err != nil {
		return Proxy{}, err
	}

	if strings.Contains(ssr, "/?") {
		paramStr := ssr[strings.Index(ssr, "/?")+2:]
		ssr = ssr[:strings.Index(ssr, "/?")]

		group, err = tool.Base64DecodeString(tool.GetUrlArg(paramStr, "group"))
		if err != nil {
			return Proxy{}, err
		}
		remarks, err = tool.Base64DecodeString(tool.GetUrlArg(paramStr, "remarks"))
		if err != nil {
			return Proxy{}, err
		}
		obfsparam, err = tool.Base64DecodeString(tool.GetUrlArg(paramStr, "obfsparam"))
		if err != nil {
			return Proxy{}, err
		}
		protoparam, err = tool.Base64DecodeString(tool.GetUrlArg(paramStr, "protoparam"))
		if err != nil {
			return Proxy{}, err
		}
	}

	// 正则解析
	regex := regexp.MustCompile(`(.+):(.+):(.+):(.+):(.+):(.+)`)
	if regex.MatchString(ssr) {
		result := regex.FindStringSubmatch(ssr)
		server, port, protocol, method, obfs, password = result[1], result[2], result[3], result[4], result[5], result[6]
	}

	password, err = tool.Base64DecodeString(password)
	if err != nil {
		return Proxy{}, err
	}
	if port == "0" {
		return Proxy{}, errors.New("ssr端口不能为0")
	}
	if group == "" {
		group = "ssr_group"
	}
	if remarks == "" {
		remarks = server + ":" + port
	}

	// 开启clash的udp
	switch obfs {
	case "tls1.2_ticket_auth",
		"tls1.2_ticket_auth_compatible",
		"tls1.2_ticket_fastauth",
		"tls1.2_ticket_fastauth_compatible":
		udp = true
	}

	// 构造节点
	proxy := Proxy{}
	// TODO: 是否存放后在解析为对应的ss节点
	// if (obfs == "" || obfs == "plain") && (protocol == "" || protocol == "origin") {
	// 	switch method {
	// 	case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
	// 		"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
	// 		"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
	// 		"rc4-md5", "chacha20", "chacha20-ietf", "xchacha20",
	// 		"chacha20-ietf-poly1305", "xchacha20-ietf-poly1305":
	// 		proxy.ssConstruct(group, remarks, server, port, password, method, "",
	// 			"", &udp, nil, nil, nil)
	// 		return proxy, nil
	// 	}
	// }

	proxy.ssrConstruct(group, remarks, server, port, protocol, method, obfs, password,
		obfsparam, protoparam, &udp, nil, nil)
	return proxy, nil
}

func ProxieToSsr(node Proxy) string {
	proxyStr := "ssr://"
	base64Str := node.Server + ":" + cast.ToString(node.Port)
	if node.Type == "ss" {
		// 判断是否符合协议
		if tool.Contains(SsrCiphers, node.EncryptMethod) && node.Plugin == "" {
			base64Str += ":origin:" + node.EncryptMethod + ":plain:"
			base64Str += tool.Base64EncodeString(node.Password) + "/?group=" + tool.Base64EncodeString(node.Group) + "&remarks=" + tool.Base64EncodeString(node.Name)
			proxyStr += tool.Base64EncodeString(base64Str)
			return proxyStr
		}
		return proxyStr
	} else if node.Type == "ssr" {
		base64Str += ":" + node.Protocol + ":" + node.EncryptMethod + node.OBFS + ":"
		base64Str += tool.Base64EncodeString(node.Password) + "/?group=" + tool.Base64EncodeString(node.Group) + "&remarks=" + tool.Base64EncodeString(node.Name)
		base64Str += "&obfsparam=" + tool.Base64EncodeString(node.OBFSParam) + "&protoparam=" + tool.Base64EncodeString(node.ProtocolParam)
		proxyStr += tool.Base64EncodeString(base64Str)
		return proxyStr
	}

	return ""
}

func SsrToString(proxyList ProxyList) string {
	var ssStrings strings.Builder
	for _, node := range proxyList {
		if nodeStr := ProxieToSsr(node); nodeStr != "" {
			ssStrings.WriteString(nodeStr + "\n")
		}
	}

	return tool.Base64EncodeString(ssStrings.String())
}
