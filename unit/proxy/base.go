package proxy

import (
	"fmt"
	"strconv"
	"strings"
	"text/template"

	"github.com/Tidra/EasyGetProxy/unit/config"
	"github.com/Tidra/EasyGetProxy/unit/tool"
)

const (
	httpHeader      = "http://"
	httpsHeader     = "https://"
	socks5Header    = "socks5://"
	ssHeader        = "ss://"
	ssrHeader       = "ssr://"
	vlessHeader     = "vless://"
	vmessHeader     = "vmess://"
	trojanHeader    = "trojan://"
	hysteriaHeader  = "hysteria://"
	hy2Header       = "hy2://"
	hysteria2Header = "hysteria2://"
	snellHeader     = "snell://"
)

// ParseProxy 解析代理链接，根据链接前缀调用不同的解析函数
func ParseProxy(proxy string) (Proxy, error) {
	// log.LogDebug(proxy)
	switch {
	case strings.HasPrefix(proxy, httpHeader), strings.HasPrefix(proxy, httpsHeader):
		return explodeHTTP(proxy)
	case strings.HasPrefix(proxy, socks5Header):
		return explodeSocks5(proxy)
	case strings.HasPrefix(proxy, ssrHeader):
		return explodeSSR(proxy)
	case strings.HasPrefix(proxy, vlessHeader):
		return explodeVless(proxy)
	case strings.HasPrefix(proxy, vmessHeader):
		return explodeVmess(proxy)
	case strings.HasPrefix(proxy, ssHeader):
		return explodeSS(proxy)
	case strings.HasPrefix(proxy, trojanHeader):
		return explodeTrojan(proxy)
	case strings.HasPrefix(proxy, hysteriaHeader):
		return explodeHysteria(proxy)
	case strings.HasPrefix(proxy, hy2Header), strings.HasPrefix(proxy, hysteria2Header):
		return explodeHy2(proxy)
	case strings.HasPrefix(proxy, snellHeader):
		return explodeSnell(proxy)
	}

	return nil, fmt.Errorf("无法识别代理连接, %s", proxy)
}

// UniqAppendProxy 向代理列表中唯一添加一个代理
func (pl *ProxyList) UniqAppendProxy(newProxy Proxy) {
	// 检查 pl 指向的 ProxyList 是否为 nil
	if pl == nil {
		// 如果 pl 本身为 nil，创建一个新的 ProxyList 指针
		newList := make(ProxyList, 0)
		pl = &newList
	} else if *pl == nil {
		// 如果 pl 指向的 ProxyList 为 nil，初始化它
		*pl = make(ProxyList, 0)
	}
	for _, p := range *pl {
		if p.GetIdentifier() == newProxy.GetIdentifier() {
			// 如果代理已经存在，抛弃新的代理
			return
		}
	}
	*pl = append(*pl, newProxy)
}

// UniqAppendProxys 向代理列表中唯一添加多个代理
func (pl *ProxyList) UniqAppendProxys(newProxyList ProxyList) {
	// 检查 pl 指向的 ProxyList 是否为 nil
	if pl == nil {
		// 如果 pl 本身为 nil，创建一个新的 ProxyList 指针
		newList := make(ProxyList, 0)
		pl = &newList
	} else if *pl == nil {
		// 如果 pl 指向的 ProxyList 为 nil，初始化它
		*pl = make(ProxyList, 0)
	}
	for _, newProxy := range newProxyList {
		exists := false
		for _, p := range *pl {
			if p.GetIdentifier() == newProxy.GetIdentifier() {
				exists = true
				break
			}
		}
		if !exists {
			*pl = append(*pl, newProxy)
		}
	}
}

// Filter 根据代理类型、国家和排除国家筛选代理列表
func (pl ProxyList) Filter(proxyTypes, proxyNotTypes, proxyCountry, proxyNotCountry, proxySpeed string, isOnlyValid bool) ProxyList {
	newProxyList := make(ProxyList, 0)

	if proxyTypes == "all" {
		proxyTypes = ""
	}
	types := strings.Split(proxyTypes, ",")
	notTypes := strings.Split(proxyNotTypes, ",")
	countries := strings.Split(proxyCountry, ",")
	notCountries := strings.Split(proxyNotCountry, ",")
	speeds := strings.Split(proxySpeed, ",")
	minSpeed, _ := strconv.ParseFloat(speeds[0], 64)
	maxSpeed := 0.0
	if len(speeds) > 1 {
		maxSpeed, _ = strconv.ParseFloat(speeds[1], 64)
	}

	for _, p := range pl {
		if isOnlyValid && !p.IsValid() {
			continue
		}
		if proxyTypes != "" && !tool.Contains(types, p.GetType()) {
			continue
		}
		if proxyNotTypes != "" && tool.Contains(notTypes, p.GetType()) {
			continue
		}
		if proxyCountry != "" && !tool.Contains(countries, p.GetCountry()) {
			continue
		}
		if proxyNotCountry != "" && tool.Contains(notCountries, p.GetCountry()) {
			continue
		}
		if minSpeed > 0 && p.GetSpeed() < minSpeed {
			continue
		}
		if maxSpeed > 0 && p.GetSpeed() > maxSpeed {
			continue
		}

		newProxyList = append(newProxyList, p)
	}
	return newProxyList
}

// RenameAll 重命名代理列表中所有代理的名称
func (pl ProxyList) RenameAll() ProxyList {
	emojiData := tool.InitEmojiData()
	tmpl, err := template.New("rename").Parse(config.Config.RenameFormat)
	if err != nil {
		// 处理模板解析错误，这里简单使用默认格式
		tmpl = template.Must(template.New("rename").Parse("[{{.Type}}]{{.Country}}{{.Num}}"))
	}

	for i, p := range pl {
		var newName strings.Builder
		// 准备模板数据
		data := struct {
			Name     string
			Type     string
			Speed    string
			Country  string
			Identity string
			Num      int
		}{
			Name:     p.GetOriginName(),
			Type:     p.GetType(),
			Speed:    fmt.Sprintf("%.2fmb/s", p.GetSpeed()),
			Country:  emojiData.GetEmoji(p.GetCountry()) + p.GetCountry(),
			Identity: p.GetIdentifier(),
			Num:      i + 1,
		}
		err := tmpl.Execute(&newName, data)
		if err != nil {
			newName.Reset()
			// 处理模板执行错误，这里简单使用默认格式
			defaultTmpl := template.Must(template.New("default").Parse("[{{.Type}}]{{.Country}}{{.Num}}"))
			defaultTmpl.Execute(&newName, data)
		}
		p.SetName(newName.String())
	}
	return pl
}

// Count 统计代理列表中不同类型和有效代理的数量
func (pl ProxyList) Count() (int, int, int, int, int, int, int, int, int, int) {
	allProxiesCount := 0
	usefullProxiesCount := 0
	ssrProxiesCount := 0
	ssProxiesCount := 0
	vlessProxiesCount := 0
	vmessProxiesCount := 0
	trojanProxiesCount := 0
	hysteriaProxiesCount := 0
	hysteria2ProxiesCount := 0
	snellProxiesCount := 0

	for _, p := range pl {
		allProxiesCount++
		if !p.IsValid() {
			continue
		}

		usefullProxiesCount++
		switch p.GetType() {
		case "ssr":
			ssrProxiesCount++
		case "ss":
			ssProxiesCount++
		case "vless":
			vlessProxiesCount++
		case "vmess":
			vmessProxiesCount++
		case "trojan":
			trojanProxiesCount++
		case "hysteria":
			hysteriaProxiesCount++
		case "hysteria2":
			hysteria2ProxiesCount++
		case "snell":
			snellProxiesCount++
		}
	}
	return allProxiesCount, usefullProxiesCount, ssrProxiesCount, ssProxiesCount, vlessProxiesCount, vmessProxiesCount, trojanProxiesCount, hysteriaProxiesCount, hysteria2ProxiesCount, snellProxiesCount
}

// SsrToString 将代理列表中的 ssr/ss 代理转换为 Base64 编码的字符串
func SsrToString(proxyList ProxyList) string {
	var ssrStrings []string
	for _, node := range proxyList {
		switch node.GetType() {
		case "ssr", "ss":
			if paramToString, ok := node.(ParamToString); ok {
				nodeStr := paramToString.ToStringWithParam("ssr")
				ssrStrings = append(ssrStrings, nodeStr)
			}
		}
	}
	return tool.Base64EncodeString(strings.Join(ssrStrings, "\n"))
}

// SsToString 将代理列表中的 ss 代理转换为 Base64 编码的字符串
func SsToString(proxyList ProxyList) string {
	var ssStrings []string
	for _, node := range proxyList {
		switch node.GetType() {
		case "ssr", "ss":
			if paramToString, ok := node.(ParamToString); ok {
				nodeStr := paramToString.ToStringWithParam("ss")
				ssStrings = append(ssStrings, nodeStr)
			}
		}
	}
	return tool.Base64EncodeString(strings.Join(ssStrings, "\n"))
}

// VmessToString 将代理列表中的 vmess 代理转换为 Base64 编码的字符串
func VmessToString(proxyList ProxyList) string {
	var vmessStrings strings.Builder
	for _, node := range proxyList {
		if node.GetType() == "vmess" {
			nodeStr := node.ToString()
			vmessStrings.WriteString(nodeStr + "\n")
		}
	}
	return tool.Base64EncodeString(vmessStrings.String())
}

// TrojanToString 将代理列表中的 trojan 代理转换为 Base64 编码的字符串
func TrojanToString(proxyList ProxyList) string {
	var trojanStrings strings.Builder
	for _, node := range proxyList {
		if node.GetType() == "trojan" {
			nodeStr := node.ToString()
			trojanStrings.WriteString(nodeStr + "\n")
		}
	}
	return tool.Base64EncodeString(trojanStrings.String())
}

// TrojanToString 将代理列表中的 trojan 代理转换为 Base64 编码的字符串
func V2rayToString(proxyList ProxyList) string {
	var v2rayStrings strings.Builder
	for _, node := range proxyList {
		nodeStr := node.ToString()
		v2rayStrings.WriteString(nodeStr + "\n")
	}
	return tool.Base64EncodeString(v2rayStrings.String())
}
