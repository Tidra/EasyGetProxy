package app

import (
	"encoding/json"
	"os"
	"time"

	"github.com/Tidra/EasyGetProxy/unit/proxy"
	"github.com/patrickmn/go-cache"
)

var c = cache.New(cache.NoExpiration, 10*time.Minute)

func GetProxies(key string) proxy.ProxyList {
	result, found := c.Get(key)
	if found {
		return result.(proxy.ProxyList)
	}
	return nil
}

func SetProxies(key string, proxies proxy.ProxyList) {
	c.Set(key, proxies, cache.NoExpiration)
}

func SetString(key, value string) {
	c.Set(key, value, cache.NoExpiration)
}

func GetString(key string) string {
	result, found := c.Get(key)
	if found {
		return result.(string)
	}
	return ""
}

// 保存到文件
func SaveCacheToFile(filename string) error {
	proxies := GetProxies("all")
	if proxies == nil {
		return nil
	}
	b, err := json.Marshal(proxies)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, b, 0644)
}

// 从文件加载
func LoadCacheFromFile(filename string) (proxy.ProxyList, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var proxies proxy.ProxyList
	if err := json.Unmarshal(b, &proxies); err != nil {
		return nil, err
	}
	SetProxies("all", proxies) // 重新放回 go-cache
	return proxies, nil
}
