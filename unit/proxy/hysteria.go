package proxy

import (
	"net/url"

	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/spf13/cast"
)

// https://hysteria.network/docs/uri-scheme/
// hysteria://host:port?protocol=udp&auth=123456&peer=sni.domain&insecure=1&upmbps=100&downmbps=100&alpn=hysteria&obfs=xplus&obfsParam=123456#remarks
func hysteriaConf(body string) (any, error) {
	u, err := url.Parse(body)
	if err != nil {
		log.LogError("parse hysteria failed, err: %v", err)
		return nil, err
	}

	query := u.Query()
	return &ClashHysteria{
		Name:                u.Fragment,
		Type:                "hysteria",
		Server:              u.Hostname(),
		Port:                cast.ToInt(u.Port()),
		AuthStr:             query.Get("auth"),
		Obfs:                query.Get("obfs"),
		Alpn:                []string{query.Get("alpn")},
		Protocol:            query.Get("protocol"),
		Up:                  query.Get("upmbps"),
		Down:                query.Get("downmbps"),
		Sni:                 query.Get("peer"),
		SkipCertVerify:      cast.ToBool(query.Get("insecure")),
		RecvWindowConn:      cast.ToInt(query.Get("recv-window-conn")),
		RecvWindow:          cast.ToInt(query.Get("recv-window")),
		Ca:                  query.Get("ca"),
		CaStr:               query.Get("ca-str"),
		DisableMtuDiscovery: cast.ToBool(query.Get("disable_mtu_discovery")),
		Fingerprint:         query.Get("fingerprint"),
		FastOpen:            cast.ToBool(query.Get("fast-open")),
	}, nil
}
