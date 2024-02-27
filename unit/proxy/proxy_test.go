package proxy

import (
	"testing"

	"github.com/Tidra/EasyGetProxy/unit/log"
)

func Test(t *testing.T) {
	// ssr := "ssr://dHcxLWpxeGguZGRucy5uZXQ6MzIzNjE6YXV0aF9hZXMxMjhfbWQ1OmNoYWNoYTIwOmh0dHBfc2ltcGxlOmFGbHhUMUZsVUEvP29iZnNwYXJhbT1aRzkzYm14dllXUXVkMmx1Wkc5M2MzVndaR0YwWlM1amIyMCZwcm90b3BhcmFtPU5Eb3liRVZyTjNFJnJlbWFya3M9UUZOVFVsUlBUMHhmZEhjeExXcHhlR2d1WkdSdWN5NXVaWFEmZ3JvdXA9VTFOU1ZFOVBUQzVEVDAwZzVvNm82WUNC"
	// // ssr = "https://free.dsdog.tk/ss/sub"
	// a, err := explodeSSR(ssr)
	// if err != nil {
	// 	log.LogError("err: %v", err)
	// }
	// log.LogInfo("Info %+v", a)

	// lnk := "trojan-go://f@uck.me/?sni=microsoft.com&type=ws&path=%2Fgo&encryption=ss%3Baes-256-gcm%3Afuckgfw"
	// vmess := "vmess://eyJ2IjoyLCJwcyI6ImdpdGh1Yi5jb20vcmF3IiwiYWRkIjoiMTAzLjg5LjEwLjExIiwicG9ydCI6NDQzLCJpZCI6ImQwZTI2NjQxLWJkNjEtNDIwYy1iOGNkLTk4Y2UzODJlODFiZSIsImFpZCI6MTIzLCJuZXQiOiJ3cyIsInR5cGUiOiJub25lIiwiaG9zdCI6ImdpdGh1Yi5jb20iLCJwYXRoIjoiL3JhdyIsInRscyI6InRscyJ9"
	vmess := "vmess://eyJ2IjoiMiIsInBzIjoi8J+HuvCfh7hfVVNf576O5Zu9LT7wn4ep8J+Hql9ERV/lvrflm70iLCJhZGQiOiIxMDQuMjEuMjMwLjUxIiwicG9ydCI6ODAsImlkIjoiNzAyMjk4MmYtZGE0Yy00OGM5LWM2NjAtYjIzMTVhYmRjZjdlIiwiYWlkIjowLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJob3N0IjoiYS5wcmFwdDUuaXIiLCJwYXRoIjoiLz9lZD0yMDQ4IiwidGxzIjoiIn0="
	b, err := explodeVmess(vmess)
	if err != nil {
		log.LogError("err: %v", err)
	}
	log.LogInfo("Info %+v", b)

	// 	soc := "vmess1://c7199cd9-964b-4321-9d33-842b6fcec068@qv2ray.net:64338?encryption=none&security=tls&sni=fastgit.org#VMessTCPTLSSNI"
	// 	// soc = "vmess1://75da2e14-4d08-480b-b3cb-0079a0c51275@example.com:443/path?network=http&http.host=example.com%2Cexample1.com&tls=true&tls.allowinsecure=true#VMessTCPTLSSNI%2Cd"
	// 	c, err := explodeKitsunebi(soc)
	// 	if err != nil {
	// 		log.LogError("err: %v", err)
	// 	}
	// 	log.LogInfo("Info %+v", c)

	// 	ss := "ss://c2Fsc2EyMDpwYXNzd29yZA==@34.93.11.120:443/?plugin=v2ray%3bfast-open%3bhost%3dwww.iwuhan.me%3bloglevel%3dnone%3bmode%3dwebsocket%3bmux%3d1%3bpath%3d%2frays%3btls#5%20wss%20%E5%8D%B0%E5%BA%A6%E9%A9%AC%E5%93%88%E6%8B%89%E6%96%BD%E7%89%B9%E6%8B%89%E9%82%A6%E5%AD%9F%E4%B9%B0"
	// 	b, err = ParseProxy(ss)
	// 	if err != nil {
	// 		log.LogError("err: %v", err)
	// 	}
	// 	log.LogInfo("Info %+v", b)

	// 	ss = "ss://c2Fsc2EyMDpwYXNzd29yZA==@35.244.126.146:443/?plugin=v2ray%3bfast-open%3bhost%3dwww.iwuhan.me%3bloglevel%3dnone%3bmode%3dwebsocket%3bmux%3d1%3bpath%3d%2frays%3btls#6%20wss%20%E6%BE%B3%E5%A4%A7%E5%88%A9%E4%BA%9A%E6%96%B0%E5%8D%97%E5%A8%81%E5%B0%94%E5%A3%AB%E5%B7%9E%E6%82%89%E5%B0%BC"
	// 	d, err := explodeSS(ss)
	// 	if err != nil {
	// 		log.LogError("err: %v", err)
	// 	}
	// 	log.LogInfo("Info %+v", d)

	// 	trojan := "trojan://mypassword@myserver.com:443?type=ws&security=tls&path=%2Fmypath&sni=myserver.com#MyServer"
	// 	d, err = explodeTrojan(trojan)
	// 	if err != nil {
	// 		log.LogError("err: %v", err)
	// 	}
	// 	log.LogInfo("Info %+v", d)

	// 	clash := `proxies:
	// - {"name":"R[ss]-🇬🇧GB_01 | 4.76Mb","server":"jseyu.arvancode.eu.Org","type":"ss","port":443,"password":"Bog0ELmMM9DSxDdQ","cipher":"chacha20-ietf-poly1305"}
	// - {"name":"R[ss]-🇬🇧GB_02 | 6.09Mb","server":"series-a2-me.samanehha.co","type":"ss","port":443,"password":"Bog0ELmMM9DSxDdQ","cipher":"chacha20-ietf-poly1305"}
	// - {"name":"[ssr]_03","server":"222.186.20.102","type":"ssr","port":41228,"password":"http://cc.ax/","cipher":"aes-256-cfb","protocol":"auth_aes128_md5","protocol-param":"165400:Hr2aXO","obfs":"plain","obfs-param":"data.bilibili.com/ed5a2165400"}
	// - {"name":"[trojan]🇦🇪AE_04 | 3.50Mb","server":"139.185.48.248","type":"trojan","country":"🇦🇪AE","port":37902,"password":"46fac810-0332-471a-a074-bdca7824211e","sni":"ua01.bsawc.shop","skip-cert-verify":true,"udp":true}
	// - {"name":"R[vmess]🇨🇴CO-🇮🇷IR_17 | 4.49Mb","server":"188.114.96.113","type":"vmess","country":"🇨🇴CO","port":80,"uuid":"7022982f-da4c-48c9-c660-b2315abdcf7e","alterId":0,"cipher":"auto","network":"ws","servername":"a.prapt5.ir","http-opts":{},"h2-opts":{},"skip-cert-verify":true,"ws-opts":{"path":"/?ed=2048","headers":{"HOST":"a.prapt5.ir"}}}
	// - {"name":"[ss]🇩🇪DE_18 | 5.65Mb","server":"80.92.204.106","type":"ss","country":"🇩🇪DE","port":9094,"password":"rpgbNnU9rDDU4aWZ","cipher":"aes-256-cfb"}
	// - {"name":"R[trojan]🇩🇪DE-🇩🇪DE_19 | 1.33Mb","server":"5.104.108.109","type":"trojan","country":"🇩🇪DE","port":443,"password":"45a8d20d-9a78-4be4-a74a-ab3b9e84e34e","sni":"20-24-33-134.nhost.00cdn.com","skip-cert-verify":true,"udp":true}
	// - {"name":"R[trojan]🇩🇪DE-🇩🇪DE_20 | 0.27Mb","server":"5.104.108.120","type":"trojan","country":"🇩🇪DE","port":443,"password":"45a8d20d-9a78-4be4-a74a-ab3b9e84e34e","sni":"20-24-33-134.nhost.00cdn.com","skip-cert-verify":true,"udp":true}
	// - {"name":"R[vmess]🏁 ZZ-🇬🇧GB_58 | 7.34Mb","server":"104.18.202.250","type":"vmess","country":"🏁 ZZ","port":2082,"uuid":"03fcc618-b93d-6796-6aed-8a38c975d581","alterId":0,"cipher":"auto","network":"ws","servername":"erfannewfreenodes.vdmmswyzmzigonvnjk443.workers.dev","http-opts":{},"h2-opts":{},"skip-cert-verify":true,"ws-opts":{"path":"/nina.bond/linkvws","headers":{"HOST":"erfannewfreenodes.vdmmswyzmzigonvnjk443.workers.dev"}}}
	// `
	// 	e, err := ExplodeClash(clash)
	// 	if err != nil {
	// 		log.LogError("err: %v", err)
	// 	}
	// 	log.LogInfo("Info %+v", e)
	// 	ProxiesToClash(e)
}
