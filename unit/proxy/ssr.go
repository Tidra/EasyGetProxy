package proxy

import (
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/tool"
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
	if (obfs == "" || obfs == "plain") && (protocol == "" || protocol == "origin") {
		switch method {
		case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
			"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
			"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
			"rc4-md5", "chacha20", "chacha20-ietf", "xchacha20",
			"chacha20-ietf-poly1305", "xchacha20-ietf-poly1305":
			proxy.ssConstruct(group, remarks, server, port, password, method, "",
				nil, &udp, nil, nil, nil)
			return proxy, nil
		}
	}

	proxy.ssrConstruct(group, remarks, server, port, protocol, method, obfs, password,
		obfsparam, protoparam, &udp, nil, nil)
	return proxy, nil
}

// ssr://server:port:protocol:method:obfs:base64(password)/?obfsparam=base64()&protoparam=base64()&remarks=base64()&group=base64()
// 解析函数
func ssrConf(linkString string) (ClashSSR, error) {
	rawSSRConfig, err := tool.Base64DecodeByte(linkString)
	if err != nil {
		return ClashSSR{}, err
	}
	params := strings.Split(string(rawSSRConfig), `:`)

	if len(params) != 6 {
		return ClashSSR{}, errors.New("ssr连接参数不足6个")
	}
	ssr := ClashSSR{}
	ssr.Type = "ssr"
	ssr.UDP = false
	ssr.Server = params[SSRServer]
	ssr.Port = params[SSRPort]
	ssr.Protocol = params[SSRProtocol]
	ssr.Cipher = params[SSRCipher]
	ssr.OBFS = params[SSROBFS]

	// 如果兼容ss协议，就转换为clash的ss配置
	// https://github.com/Dreamacro/clash
	if ssr.Protocol == "origin" && ssr.OBFS == "plain" {
		switch ssr.Cipher {
		case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
			"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
			"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
			"rc4-md5", "chacha20", "chacha20-ietf", "xchacha20",
			"chacha20-ietf-poly1305", "xchacha20-ietf-poly1305":
			ssr.Type = "ss"
		}
	}

	// 开启clash的udp
	switch ssr.OBFS {
	case "tls1.2_ticket_auth",
		"tls1.2_ticket_auth_compatible",
		"tls1.2_ticket_fastauth",
		"tls1.2_ticket_fastauth_compatible":
		ssr.UDP = true
	}

	suffix := strings.Split(params[SSRSuffix], "/?")
	if len(suffix) != 2 {
		return ClashSSR{}, errors.New("ssr额外参数不足")
	}
	passwordBase64 := suffix[0]
	password, err := tool.Base64DecodeByte(passwordBase64)
	if err != nil {
		return ClashSSR{}, err
	}
	ssr.Password = string(password)

	m, err := url.ParseQuery(suffix[1])
	if err != nil {
		return ClashSSR{}, err
	}

	for k, v := range m {
		de, err := tool.Base64DecodeByte(v[0])
		if err != nil {
			return ClashSSR{}, err
		}
		switch k {
		case "obfsparam":
			ssr.OBFSParam = string(de)
			continue
		case "protoparam":
			ssr.ProtocolParam = string(de)
			continue
		case "remarks":
			ssr.Name = string(de)
			continue
		case "group":
			continue
		}
	}
	return ssr, nil
}
