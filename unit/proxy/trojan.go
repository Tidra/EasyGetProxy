package proxy

import (
	"errors"
	"net/url"
)

func trojanConf(s string) (ClashTrojan, error) {
	s, err := url.PathUnescape(s)
	if err != nil {
		return ClashTrojan{}, err
	}

	findStr := trojanReg.FindStringSubmatch(s)
	if len(findStr) == 6 {
		return ClashTrojan{
			Name:     findStr[5],
			Type:     "trojan",
			Server:   findStr[2],
			Password: findStr[1],
			Sni:      findStr[4],
			Port:     findStr[3],
		}, nil
	}

	findStr = trojanReg2.FindStringSubmatch(s)
	if len(findStr) < 5 {
		return ClashTrojan{}, errors.New("trojan连接参数少于5个")
	}

	return ClashTrojan{
		Name:     findStr[4],
		Type:     "trojan",
		Server:   findStr[2],
		Password: findStr[1],
		Port:     findStr[3],
	}, nil
}
