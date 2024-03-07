package proxy

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/spf13/cast"
)

const (
	ssrHeader      = "ssr://"
	vmessHeader    = "vmess://"
	ssHeader       = "ss://"
	trojanHeader   = "trojan://"
	hysteriaHeader = "hysteria://"
)

// var (
// 	ssReg  = regexp.MustCompile(`(?m)ss://(\w+)@([^:]+):(\d+)\?plugin=([^;]+);\w+=(\w+)(?:;obfs-host=)?([^#]+)?#(.+)`)
// 	ssReg2 = regexp.MustCompile(`(?m)([\-0-9a-z]+):(.+)@(.+):(\d+)(.+)?#(.+)`)
// 	ssReg  = regexp.MustCompile(`(?m)([^@]+)(@.+)?#?(.+)?`)

// 	trojanReg  = regexp.MustCompile(`(?m)^trojan://(.+)@(.+):(\d+)\?allowInsecure=\d&peer=(.+)#(.+)`)
// 	trojanReg2 = regexp.MustCompile(`(?m)^trojan://(.+)@(.+):(\d+)#(.+)$`)
// )

func ParseProxy(proxy string) (Proxy, error) {
	// log.LogDebug(proxy)
	switch {
	case strings.HasPrefix(proxy, ssrHeader):
		// return ssrConf(subProtocolBody(proxy, ssrHeader))
		return explodeSSR(proxy)
	case strings.HasPrefix(proxy, vmessHeader):
		// return v2rConf(subProtocolBody(proxy, vmessHeader))
		return explodeVmess(proxy)
	case strings.HasPrefix(proxy, ssHeader):
		// return ssConf(subProtocolBody(proxy, ssHeader))
		return explodeSS(proxy)
	case strings.HasPrefix(proxy, trojanHeader):
		// return trojanConf(subProtocolBody(proxy, trojanHeader))
		return explodeTrojan(proxy)
		// case strings.HasPrefix(proxy, hysteriaHeader):
		// 	return hysteriaConf(proxy)
	}

	return Proxy{}, fmt.Errorf("无法识别代理连接, %s", proxy)
}

func (proxy *Proxy) commonConstruct(proxyType, group, name, server string, port any,
	udp, tfo, scv, tls13 *bool) {
	proxy.Type = proxyType
	proxy.Group = group
	proxy.Name = name
	proxy.Server = server
	proxy.Port = cast.ToInt(port)
	if udp != nil {
		proxy.UDP = *udp
	}
	if scv != nil {
		proxy.SkipCertVerify = *scv
	}
	if tls13 != nil {
		proxy.TLS13 = *tls13
	}
}

func (proxy Proxy) IsEmpty() bool {
	return reflect.DeepEqual(proxy, Proxy{})
}

func (proxy Proxy) Identifier() string {
	return fmt.Sprintf("%s%s%d%s%s%s%s", proxy.Type, proxy.Server, proxy.Port, proxy.Username, proxy.Password, proxy.EncryptMethod, proxy.UUID)
}

func (pl *ProxyList) UniqAppendProxy(newProxy Proxy) {
	if len(*pl) == 0 {
		*pl = append(*pl, newProxy)
	}
	for _, p := range *pl {
		if p.Identifier() == newProxy.Identifier() {
			// 如果代理已经存在，抛弃新的代理
			return
		}
	}
	*pl = append(*pl, newProxy)
}

func (pl *ProxyList) UniqAppendProxys(newProxyList ProxyList) {
	for _, newProxy := range newProxyList {
		exists := false
		for _, p := range *pl {
			if p.Identifier() == newProxy.Identifier() {
				exists = true
				break
			}
		}
		if !exists {
			*pl = append(*pl, newProxy)
		}
	}
}

func (pl ProxyList) Filter(proxyTypes string, proxyCountry string, proxyNotCountry string) ProxyList {
	newProxyList := make(ProxyList, 0)

	if proxyTypes == "all" {
		proxyTypes = ""
	}
	types := strings.Split(proxyTypes, ",")
	countries := strings.Split(proxyCountry, ",")
	notCountries := strings.Split(proxyNotCountry, ",")

	for _, p := range pl {
		if !p.IsValid {
			continue
		}
		if proxyTypes != "" {
			if !tool.Contains(types, p.Type) {
				continue
			}
		}
		if proxyCountry != "" {
			if !tool.Contains(countries, p.Country) {
				continue
			}
		}
		if proxyNotCountry != "" {
			if tool.Contains(notCountries, p.Country) {
				continue
			}
		}
		newProxyList = append(newProxyList, p)
	}
	return newProxyList
}

func (pl ProxyList) RenameAll() ProxyList {
	for i, p := range pl {
		newName := fmt.Sprintf("[%s]%s_%+02v", p.Type, p.Country, i+1)
		if p.Speed > 0 {
			newName = fmt.Sprintf("%s_%.1fmb/s", newName, p.Speed)
		}
		pl[i].Name = newName
	}
	return pl
}

func (pl ProxyList) Count() (int, int, int, int, int, int) {
	allProxiesCount := 0
	usefullProxiesCount := 0
	ssrProxiesCount := 0
	ssProxiesCount := 0
	vmessProxiesCount := 0
	trojanProxiesCount := 0
	for _, p := range pl {
		allProxiesCount++
		if !p.IsValid {
			continue
		}

		usefullProxiesCount++
		switch p.Type {
		case "ssr":
			ssrProxiesCount++
		case "ss":
			ssProxiesCount++
		case "vmess":
			vmessProxiesCount++
		case "trojan":
			trojanProxiesCount++
		}
	}
	return allProxiesCount, usefullProxiesCount, ssrProxiesCount, ssProxiesCount, vmessProxiesCount, trojanProxiesCount
}
