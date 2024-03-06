package proxy

import (
	"strings"

	"github.com/spf13/cast"
)

// 设置surge版本为3
var surgeVersion = 3
var surgeSsrPath = ""

func ProxieToSurge(node Proxy) string {
	proxyStr := node.Name + " = "
	switch node.Type {
	case "ss":
		if surgeVersion >= 3 || surgeVersion == -3 {
			proxyStr += "ss, " + node.Server + ", " + cast.ToString(node.Port) + ", encrypt-method=" + node.EncryptMethod + ", password=" + node.Password
		} else {
			proxyStr += "custom, " + node.Server + ", " + cast.ToString(node.Port) + ", " + node.EncryptMethod + ", " + node.Password + ", https://github.com/pobizhe/SSEncrypt/raw/master/SSEncrypt.module"
		}
		if node.Plugin != "" && node.PluginOption != "" && strings.Contains(node.Plugin, "obfs") {
			proxyStr += "," + strings.ReplaceAll(node.PluginOption, ";", ",")
		}

	case "ssr":
		if surgeSsrPath == "" || surgeVersion < 2 {
			return ""
		}

	case "vmess":
		if (surgeVersion < 4 && surgeVersion != -3) || (node.TransferProtocol != "tcp" && node.TransferProtocol != "ws") {
			return ""
		}
		proxyStr += "vmess, " + node.Server + ", " + cast.ToString(node.Port) + ", username=" + node.UUID

		if node.TLSSecure {
			proxyStr += ", tls=true"
			if node.TLS13 {
				proxyStr += ", tls13=true"
			}
		} else {
			proxyStr += ", tls=false"
		}

		if node.AlterID == 0 {
			proxyStr += ", vmess-aead=true"
		} else {
			proxyStr += ", vmess-aead=false"
		}

		if node.TransferProtocol == "ws" {
			header := ""
			if node.Host != "" {
				proxyStr += ", ws=true, ws-path=" + node.Path + ", sni=" + node.Host
				header += "Host:" + node.Host
			} else {
				proxyStr += ", ws=true, ws-path=" + node.Path + ", sni=" + node.Server
			}
			if node.Edge != "" {
				if header != "" {
					header += "|Edge:" + node.Edge
				} else {
					header += "Edge:" + node.Edge
				}
			}
			if header != "" {
				proxyStr += ", ws-headers=" + header
			}
		}

		if node.SkipCertVerify {
			proxyStr += ", skip-cert-verify=true"
		}

	case "socks5":
		proxyStr += "socks5, " + node.Server + ", " + cast.ToString(node.Port)
		if node.Username != "" {
			proxyStr += ", username=" + node.Username
		}
		if node.Password != "" {
			proxyStr += ", password=" + node.Password
		}
		if node.SkipCertVerify {
			proxyStr += ", skip-cert-verify=true"
		}

	case "https":
		proxyStr += "https, " + node.Server + ", " + cast.ToString(node.Port) + ", " + node.Username + ", " + node.Password
		if node.SkipCertVerify {
			proxyStr += ", skip-cert-verify=true"
		}

	case "http":
		proxyStr += "http, " + node.Server + ", " + cast.ToString(node.Port)
		if node.Username != "" {
			proxyStr += ", username=" + node.Username
		}
		if node.Password != "" {
			proxyStr += ", password=" + node.Password
		}
		if node.TLSSecure {
			proxyStr += ", tls=true"
		} else {
			proxyStr += ", tls=false"
		}
		if node.SkipCertVerify {
			proxyStr += ", skip-cert-verify=true"
		}

	case "trojan":
		if surgeVersion < 4 && surgeVersion != -3 {
			return ""
		}
		proxyStr += "trojan, " + node.Server + ", " + cast.ToString(node.Port) + ", password=" + node.Password
		if node.SnellVersion != 0 {
			proxyStr += ", version=" + cast.ToString(node.SnellVersion)
		}
		if node.Host != "" {
			proxyStr += ", sni=" + node.Host
		}
		if node.SkipCertVerify {
			proxyStr += ", skip-cert-verify=true"
		}
	}

	return proxyStr
}

func SurgeToString(proxyList ProxyList) string {
	var surgeStrings strings.Builder

	for _, node := range proxyList {
		if !node.IsAlive {
			continue
		}
		if nodeStr := ProxieToSurge(node); nodeStr != "" {
			surgeStrings.WriteString(nodeStr + "\n")
		}
	}
	return surgeStrings.String()
}
