package proxy

import (
	"errors"
	"net/url"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/tool"
)

// ssr://server:port:protocol:method:obfs:base64(password)/?obfsparam=base64()&protoparam=base64()&remarks=base64()&group=base64()
// 解析函数
func ssrConf(linkString string) (ClashSSR, error) {
	rawSSRConfig, err := tool.Base64DecodeStripped(linkString)
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
	password, err := tool.Base64DecodeStripped(passwordBase64)
	if err != nil {
		return ClashSSR{}, err
	}
	ssr.Password = string(password)

	m, err := url.ParseQuery(suffix[1])
	if err != nil {
		return ClashSSR{}, err
	}

	for k, v := range m {
		de, err := tool.Base64DecodeStripped(v[0])
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

// 序列化函数
// func (c *ClashSSR) Encode() string {
// 	// 1. 组装各参数为连接串
// 	// 2. 返回编码后的连接串
// }
