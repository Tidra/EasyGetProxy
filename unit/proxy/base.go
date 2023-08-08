package proxy

import (
	"fmt"
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

func parseProxy(proxy string) (any, error) {
	switch {
	case strings.HasPrefix(proxy, ssrHeader):
		return ssrConf(subProtocolBody(proxy, ssrHeader))
	case strings.HasPrefix(proxy, vmessHeader):
		return v2rConf(subProtocolBody(proxy, vmessHeader))
	case strings.HasPrefix(proxy, ssHeader):
		return ssConf(subProtocolBody(proxy, ssHeader))
	case strings.HasPrefix(proxy, trojanHeader):
		return trojanConf(subProtocolBody(proxy, trojanHeader))
	case strings.HasPrefix(proxy, hysteriaHeader):
		return hysteriaConf(proxy)
	}

	return nil, fmt.Errorf("无法识别代理连接, %s", proxy)
}

func (proxy *Proxy) commonConstruct(proxyType string, group string, name string, server string,
	port any, udp *bool, tfo *bool, scv *bool, tls13 *bool) {
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
