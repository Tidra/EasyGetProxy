package proxy

import (
	"fmt"
	"reflect"
	"regexp"
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

var (
	//ssReg      = regexp.MustCompile(`(?m)ss://(\w+)@([^:]+):(\d+)\?plugin=([^;]+);\w+=(\w+)(?:;obfs-host=)?([^#]+)?#(.+)`)
	ssReg2 = regexp.MustCompile(`(?m)([\-0-9a-z]+):(.+)@(.+):(\d+)(.+)?#(.+)`)
	ssReg  = regexp.MustCompile(`(?m)([^@]+)(@.+)?#?(.+)?`)

	trojanReg  = regexp.MustCompile(`(?m)^trojan://(.+)@(.+):(\d+)\?allowInsecure=\d&peer=(.+)#(.+)`)
	trojanReg2 = regexp.MustCompile(`(?m)^trojan://(.+)@(.+):(\d+)#(.+)$`)
)

func subProtocolBody(proxy string, prefix string) string {
	return strings.TrimSpace(proxy[len(prefix):])
}

func ParseProxy(proxy string) (Proxy, error) {
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
		return Proxy{}, nil
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

func (proxyList *ProxyList) UniqAppendProxy(newProxy Proxy) ProxyList {
	if len(*proxyList) == 0 {
		*proxyList = append(*proxyList, newProxy)
		return *proxyList
	}
	for i := range *proxyList {
		if reflect.DeepEqual((*proxyList)[i], newProxy) {
			return *proxyList
		}
	}
	*proxyList = append(*proxyList, newProxy)
	return *proxyList
}
