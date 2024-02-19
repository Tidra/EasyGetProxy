package proxy

import (
	"net/url"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/tool"
)

func (proxy *Proxy) ssConstruct(group, remarks, server, port, password, method, plugin string,
	pluginopts *PluginOpts, udp, tfo, scv, tls13 *bool) {
	proxy.commonConstruct("ss", group, remarks, server, port, udp, tfo, scv, tls13)
	proxy.Password = password
	proxy.EncryptMethod = method
	proxy.Plugin = plugin
	proxy.PluginOption = pluginopts
}

func explodeSS(ss string) (Proxy, error) {
	var password, method, server, port, plugin, group string
	u, err := url.Parse(ss)
	if err != nil {
		return Proxy{}, err
	}

	// 分解主配置和附加参数
	remarks := u.Fragment
	if u.User.String() == "" {
		// base64的情况
		infos, err := tool.Base64DecodeString(u.Hostname())
		if err != nil {
			return Proxy{}, err
		}
		u, err = url.Parse("ss://" + infos)
		if err != nil {
			return Proxy{}, err
		}
		method = u.User.Username()
		password, _ = u.User.Password()
	} else {
		cipherInfoString, err := tool.Base64DecodeString(u.User.Username())
		if err != nil {
			return Proxy{}, err
		}
		cipherInfo := strings.SplitN(cipherInfoString, ":", 2)
		if len(cipherInfo) < 2 {
			return Proxy{}, err
		}
		method = strings.ToLower(cipherInfo[0])
		password = cipherInfo[1]
	}
	server = u.Hostname()
	port = u.Port()
	addition := u.RawQuery

	pluginOpts := new(PluginOpts)
	pluginString := strings.ReplaceAll(tool.GetUrlArg(addition, "plugin"), ";", "&")
	switch {
	case strings.Contains(pluginString, "obfs"):
		plugin = "obfs"
		pluginOpts.Mode = tool.GetUrlArg(pluginString, "obfs")
		pluginOpts.Host = tool.GetUrlArg(pluginString, "obfs-host")
	case strings.Contains(pluginString, "v2ray"):
		plugin = "v2ray-plugin"
		pluginOpts.Mode = tool.GetUrlArg(pluginString, "mode")
		pluginOpts.Host = tool.GetUrlArg(pluginString, "host")
		pluginOpts.Path = tool.GetUrlArg(pluginString, "path")
		pluginOpts.Mux = strings.Contains(pluginString, "mux")
		pluginOpts.Tls = strings.Contains(pluginString, "tls")
		pluginOpts.SkipCertVerify = true
	}
	group = tool.GetUrlArg(addition, "group")

	// 构造节点
	proxy := Proxy{}
	proxy.ssConstruct(group, remarks, server, port, password, method, plugin, pluginOpts,
		nil, nil, nil, nil)
	return proxy, nil
}

// func ssConf(s string) (ClashSS, error) {
// 	s, err := url.PathUnescape(s)
// 	if err != nil {
// 		return ClashSS{}, err
// 	}

// 	findStr := ssReg.FindStringSubmatch(s)
// 	if len(findStr) < 4 {
// 		return ClashSS{}, errors.New("ss 参数少于4个")
// 	}

// 	rawSSRConfig, err := tool.Base64DecodeByte(findStr[1])
// 	if err != nil {
// 		return ClashSS{}, err
// 	}

// 	s = strings.ReplaceAll(s, findStr[1], string(rawSSRConfig))
// 	findStr = ssReg2.FindStringSubmatch(s)

// 	ss := ClashSS{}
// 	ss.Type = "ss"
// 	ss.UDP = false
// 	ss.Cipher = findStr[1]
// 	ss.Password = findStr[2]
// 	ss.Server = findStr[3]
// 	ss.Port = findStr[4]
// 	ss.Name = findStr[6]

// 	if findStr[5] != "" && strings.Contains(findStr[5], "plugin") {
// 		query := findStr[5][strings.Index(findStr[5], "?")+1:]
// 		queryMap, err := url.ParseQuery(query)
// 		if err != nil {
// 			return ClashSS{}, err
// 		}

// 		ss.Plugin = queryMap["plugin"][0]
// 		p := new(PluginOpts)
// 		switch {
// 		case strings.Contains(ss.Plugin, "obfs"):
// 			ss.Plugin = "obfs"
// 			p.Mode = queryMap["obfs"][0]
// 			if strings.Contains(query, "obfs-host=") {
// 				p.Host = queryMap["obfs-host"][0]
// 			}
// 		case ss.Plugin == "v2ray-plugin":
// 			p.Mode = queryMap["mode"][0]
// 			if strings.Contains(query, "host=") {
// 				p.Host = queryMap["host"][0]
// 			}
// 			if strings.Contains(query, "path=") {
// 				p.Path = queryMap["path"][0]
// 			}
// 			p.Mux = strings.Contains(query, "mux")
// 			p.Tls = strings.Contains(query, "tls")
// 			p.SkipCertVerify = true
// 		}
// 		ss.PluginOpts = p
// 	}

// 	return ss, nil
// }
