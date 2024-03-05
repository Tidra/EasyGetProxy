package proxy

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/spf13/cast"
)

func (proxy *Proxy) ssConstruct(group, remarks, server, port, password, method, plugin string,
	pluginopts string, udp, tfo, scv, tls13 *bool) {
	proxy.commonConstruct("ss", group, remarks, server, port, udp, tfo, scv, tls13)
	proxy.Password = password
	proxy.EncryptMethod = method
	proxy.Plugin = plugin
	proxy.PluginOption = pluginopts
}

func explodeSS(ss string) (Proxy, error) {
	var password, method, server, port, plugin, pluginOpts string
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
	plugins := tool.GetUrlArg(u.RawQuery, "plugin")

	if pluginpos := strings.Index(plugins, ";"); pluginpos > 0 {
		plugin = plugins[:pluginpos]
		pluginOpts = plugins[pluginpos+1:]
	} else {
		plugin = plugins
	}
	// pluginOpts := new(PluginOpts)
	// pluginString := strings.ReplaceAll(tool.GetUrlArg(addition, "plugin"), ";", "&")
	// switch {
	// case strings.Contains(pluginString, "obfs"):
	// 	plugin = "obfs"
	// 	pluginOpts.Mode = tool.GetUrlArg(pluginString, "obfs")
	// 	pluginOpts.Host = tool.GetUrlArg(pluginString, "obfs-host")
	// case strings.Contains(pluginString, "v2ray"):
	// 	plugin = "v2ray-plugin"
	// 	pluginOpts.Mode = tool.GetUrlArg(pluginString, "mode")
	// 	pluginOpts.Host = tool.GetUrlArg(pluginString, "host")
	// 	pluginOpts.Path = tool.GetUrlArg(pluginString, "path")
	// 	pluginOpts.Mux = strings.Contains(pluginString, "mux")
	// 	pluginOpts.Tls = strings.Contains(pluginString, "tls")
	// 	pluginOpts.SkipCertVerify = true
	// }
	// group = tool.GetUrlArg(addition, "group")

	// 构造节点
	proxy := Proxy{}
	proxy.ssConstruct("ss_group", remarks, server, port, password, method, plugin, pluginOpts,
		nil, nil, nil, nil)
	return proxy, nil
}

func ProxieToSip002(node Proxy) string {
	proxyStr := "ss://" + tool.Base64EncodeString(node.EncryptMethod+":"+node.Password) + "@" + node.Server + ":" + cast.ToString(node.Port)
	if node.Type == "ss" {
		if node.Plugin != "" && node.PluginOption != "" {
			proxyStr += "/?plugin=" + url.QueryEscape(node.Plugin+";"+node.PluginOption)
		}
		proxyStr += "#" + url.QueryEscape(node.Name)
		return proxyStr
	} else if node.Type == "ssr" {
		// 判断是否符合协议
		if tool.Contains(SsCiphers, node.EncryptMethod) && (node.OBFS == "" || node.OBFS == "plain") && (node.Protocol == "" || node.Protocol == "origin") {
			proxyStr += "#" + url.QueryEscape(node.Name)
			return proxyStr
		}
	}

	return ""
}

func ProxieToSs(node Proxy) map[string]interface{} {
	plugin := node.Plugin
	switch node.Type {
	case "ss":
		if plugin == "simple-obfs" {
			plugin = "obfs-local"
		}
	case "ssr":
		// TODO: 是否判断是否要符合ssr条件
	default:
		return nil
	}

	proxy := map[string]interface{}{
		"remarks":     node.Name,
		"server":      node.Server,
		"server_port": node.Port,
		"method":      node.EncryptMethod,
		"password":    node.Password,
		"plugin":      plugin,
		"plugin_opts": node.PluginOption,
	}

	return proxy
}

func SsToString(proxyList ProxyList, subType int) string {
	var ssStrings strings.Builder
	if subType == 1 {
		for _, node := range proxyList {
			if nodeStr := ProxieToSip002(node); nodeStr != "" {
				ssStrings.WriteString(nodeStr + "\n")
			}
		}

		return tool.Base64EncodeString(ssStrings.String())
	} else {
		proxies := make([]map[string]interface{}, 0)
		for _, node := range proxyList {
			if proxy := ProxieToSs(node); proxy != nil {
				proxies = append(proxies, proxy)
			}
		}
		jsonData, err := json.Marshal(proxies)
		if err != nil {
			return ""
		}

		return string(jsonData)
	}

}
