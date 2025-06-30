package proxy

import (
	"strings"

	"github.com/spf13/cast"
)

// 设置surge版本为4
var surgeVersion = 4
var surgeSsrPath = ""

// ProxieToSurge 将单个代理转换为 Surge 配置格式的字符串
func ProxieToSurge(node Proxy) string {
	proxyStr := node.GetName() + " = "
	switch node.GetType() {
	case "ss":
		ssNode, ok := node.(*SSProxy)
		if !ok {
			return ""
		}
		if surgeVersion >= 3 || surgeVersion == -3 {
			proxyStr += "ss, " + ssNode.Server + ", " + cast.ToString(ssNode.Port) + ", encrypt-method=" + ssNode.EncryptMethod + ", password=" + ssNode.Password
		} else {
			proxyStr += "custom, " + ssNode.Server + ", " + cast.ToString(ssNode.Port) + ", " + ssNode.EncryptMethod + ", " + ssNode.Password + ", https://github.com/pobizhe/SSEncrypt/raw/master/SSEncrypt.module"
		}
		if ssNode.Plugin != "" && ssNode.PluginOption != "" && strings.Contains(ssNode.Plugin, "obfs") {
			proxyStr += "," + strings.ReplaceAll(ssNode.PluginOption, ";", ",")
		}

	case "ssr":
		ssrNode, ok := node.(*SSRProxy)
		if !ok {
			return ""
		}
		if surgeSsrPath == "" || surgeVersion < 2 {
			return ""
		}
		proxyStr += "ssr, " + ssrNode.Server + ", " + cast.ToString(ssrNode.Port) + ", encrypt-method=" + ssrNode.EncryptMethod + ", password=" + ssrNode.Password + ", protocol=" + ssrNode.Protocol + ", obfs=" + ssrNode.OBFS
		if ssrNode.ProtocolParam != "" {
			proxyStr += ", protocol-param=" + ssrNode.ProtocolParam
		}
		if ssrNode.OBFSParam != "" {
			proxyStr += ", obfs-param=" + ssrNode.OBFSParam
		}

	case "vmess":
		vmessNode, ok := node.(*Vmess)
		if !ok {
			return ""
		}
		if (surgeVersion < 4 && surgeVersion != -3) || (vmessNode.TransferProtocol != "tcp" && vmessNode.TransferProtocol != "ws") {
			return ""
		}
		proxyStr += "vmess, " + vmessNode.Server + ", " + cast.ToString(vmessNode.Port) + ", username=" + vmessNode.UUID

		if vmessNode.TLSSecure {
			proxyStr += ", tls=true"
			if vmessNode.TLS13 {
				proxyStr += ", tls13=true"
			}
		} else {
			proxyStr += ", tls=false"
		}

		if vmessNode.AlterID == 0 {
			proxyStr += ", vmess-aead=true"
		} else {
			proxyStr += ", vmess-aead=false"
		}

		if vmessNode.TransferProtocol == "ws" {
			header := ""
			if vmessNode.Host != "" {
				proxyStr += ", ws=true, ws-path=" + vmessNode.Path + ", sni=" + vmessNode.Host
				header += "Host:" + vmessNode.Host
			} else {
				proxyStr += ", ws=true, ws-path=" + vmessNode.Path + ", sni=" + vmessNode.Server
			}
			if vmessNode.Edge != "" {
				if header != "" {
					header += "|Edge:" + vmessNode.Edge
				} else {
					header += "Edge:" + vmessNode.Edge
				}
			}
			if header != "" {
				proxyStr += ", ws-headers=" + header
			}
		}

		if vmessNode.SkipCertVerify {
			proxyStr += ", skip-cert-verify=true"
		}

	case "socks5":
		socks5Node, ok := node.(*Socks5Proxy)
		if !ok {
			return ""
		}
		proxyStr += "socks5, " + socks5Node.Server + ", " + cast.ToString(socks5Node.Port)
		if socks5Node.Username != "" {
			proxyStr += ", username=" + socks5Node.Username
		}
		if socks5Node.Password != "" {
			proxyStr += ", password=" + socks5Node.Password
		}
		if socks5Node.SkipCertVerify {
			proxyStr += ", skip-cert-verify=true"
		}

	case "https":
		httpNode, ok := node.(*HTTPProxy)
		if !ok {
			return ""
		}
		proxyStr += "https, " + httpNode.Server + ", " + cast.ToString(httpNode.Port) + ", " + httpNode.Username + ", " + httpNode.Password
		if httpNode.SkipCertVerify {
			proxyStr += ", skip-cert-verify=true"
		}

	case "http":
		httpNode, ok := node.(*HTTPProxy)
		if !ok {
			return ""
		}
		proxyStr += "http, " + httpNode.Server + ", " + cast.ToString(httpNode.Port)
		if httpNode.Username != "" {
			proxyStr += ", username=" + httpNode.Username
		}
		if httpNode.Password != "" {
			proxyStr += ", password=" + httpNode.Password
		}
		if httpNode.TLSSecure {
			proxyStr += ", tls=true"
		} else {
			proxyStr += ", tls=false"
		}
		if httpNode.SkipCertVerify {
			proxyStr += ", skip-cert-verify=true"
		}

	case "trojan":
		trojanNode, ok := node.(*TrojanProxy)
		if !ok {
			return ""
		}
		if surgeVersion < 4 && surgeVersion != -3 {
			return ""
		}
		proxyStr += "trojan, " + trojanNode.Server + ", " + cast.ToString(trojanNode.Port) + ", password=" + trojanNode.Password
		// if trojanNode.SnellVersion != 0 {
		// 	proxyStr += ", version=" + cast.ToString(trojanNode.SnellVersion)
		// }
		if trojanNode.Host != "" {
			proxyStr += ", sni=" + trojanNode.Host
		}
		if trojanNode.SkipCertVerify {
			proxyStr += ", skip-cert-verify=true"
		}
	}

	return proxyStr
}

// SurgeToString 将代理列表转换为 Surge 配置格式的字符串
func SurgeToString(proxyList ProxyList) string {
	var surgeStrings strings.Builder

	for _, node := range proxyList {
		// if !node.IsValid() {
		// 	continue
		// }
		if nodeStr := ProxieToSurge(node); nodeStr != "" {
			surgeStrings.WriteString(nodeStr + "\n")
		}
	}
	return surgeStrings.String()
}
