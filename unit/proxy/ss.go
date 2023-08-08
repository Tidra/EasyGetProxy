package proxy

import (
	"errors"
	"net/url"
	"strings"

	"github.com/Tidra/EasyGetProxy/unit/tool"
)

func ssConf(s string) (ClashSS, error) {
	s, err := url.PathUnescape(s)
	if err != nil {
		return ClashSS{}, err
	}

	findStr := ssReg.FindStringSubmatch(s)
	if len(findStr) < 4 {
		return ClashSS{}, errors.New("ss 参数少于4个")
	}

	rawSSRConfig, err := tool.Base64DecodeStripped(findStr[1])
	if err != nil {
		return ClashSS{}, err
	}

	s = strings.ReplaceAll(s, findStr[1], string(rawSSRConfig))
	findStr = ssReg2.FindStringSubmatch(s)

	ss := ClashSS{}
	ss.Type = "ss"
	ss.UDP = false
	ss.Cipher = findStr[1]
	ss.Password = findStr[2]
	ss.Server = findStr[3]
	ss.Port = findStr[4]
	ss.Name = findStr[6]

	if findStr[5] != "" && strings.Contains(findStr[5], "plugin") {
		query := findStr[5][strings.Index(findStr[5], "?")+1:]
		queryMap, err := url.ParseQuery(query)
		if err != nil {
			return ClashSS{}, err
		}

		ss.Plugin = queryMap["plugin"][0]
		p := new(PluginOpts)
		switch {
		case strings.Contains(ss.Plugin, "obfs"):
			ss.Plugin = "obfs"
			p.Mode = queryMap["obfs"][0]
			if strings.Contains(query, "obfs-host=") {
				p.Host = queryMap["obfs-host"][0]
			}
		case ss.Plugin == "v2ray-plugin":
			p.Mode = queryMap["mode"][0]
			if strings.Contains(query, "host=") {
				p.Host = queryMap["host"][0]
			}
			if strings.Contains(query, "path=") {
				p.Path = queryMap["path"][0]
			}
			p.Mux = strings.Contains(query, "mux")
			p.Tls = strings.Contains(query, "tls")
			p.SkipCertVerify = true
		}
		ss.PluginOpts = p
	}

	return ss, nil
}
