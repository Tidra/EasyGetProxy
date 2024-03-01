package proxy

import (
	"fmt"
	"reflect"
	"strings"

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

func (pl *ProxyList) UniqAppendProxy(newProxy Proxy) {
	if len(*pl) == 0 {
		*pl = append(*pl, newProxy)
	}
	for _, p := range *pl {
		if reflect.DeepEqual(p, newProxy) {
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
			if reflect.DeepEqual(p, newProxy) {
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

	findKey := func(arr []string, key string) bool {
		for _, i := range arr {
			if i == key {
				return true
			}
		}
		return false
	}

	for _, p := range pl {
		if proxyTypes != "" {
			if !findKey(types, p.Type) {
				continue
			}
		}
		if proxyCountry != "" {
			if !findKey(countries, p.Country) {
				continue
			}
		}
		if proxyNotCountry != "" {
			if findKey(notCountries, p.Country) {
				continue
			}
		}
		newProxyList = append(newProxyList, p)
	}
	return newProxyList
}
