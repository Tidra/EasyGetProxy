package proxy

import (
	"testing"

	"github.com/Tidra/EasyGetProxy/unit/log"
)

func Test(t *testing.T) {
	ssr := "ssr://dHcxLWpxeGguZGRucy5uZXQ6MzIzNjE6YXV0aF9hZXMxMjhfbWQ1OmNoYWNoYTIwOmh0dHBfc2ltcGxlOmFGbHhUMUZsVUEvP29iZnNwYXJhbT1aRzkzYm14dllXUXVkMmx1Wkc5M2MzVndaR0YwWlM1amIyMCZwcm90b3BhcmFtPU5Eb3liRVZyTjNFJnJlbWFya3M9UUZOVFVsUlBUMHhmZEhjeExXcHhlR2d1WkdSdWN5NXVaWFEmZ3JvdXA9VTFOU1ZFOVBUQzVEVDAwZzVvNm82WUNC"
	// ssr = "https://free.dsdog.tk/ss/sub"
	a, err := explodeSSR(ssr)
	if err != nil {
		log.LogError("err: %v", err)
	}
	log.LogInfo("Info %+v", a)

	// lnk := "trojan-go://f@uck.me/?sni=microsoft.com&type=ws&path=%2Fgo&encryption=ss%3Baes-256-gcm%3Afuckgfw"
	vmess := "vmess://eyJ2IjoyLCJwcyI6ImdpdGh1Yi5jb20vcmF3IiwiYWRkIjoiMTAzLjg5LjEwLjExIiwicG9ydCI6NDQzLCJpZCI6ImQwZTI2NjQxLWJkNjEtNDIwYy1iOGNkLTk4Y2UzODJlODFiZSIsImFpZCI6MTIzLCJuZXQiOiJ3cyIsInR5cGUiOiJub25lIiwiaG9zdCI6ImdpdGh1Yi5jb20iLCJwYXRoIjoiL3JhdyIsInRscyI6InRscyJ9"
	b, err := parseProxy(vmess)
	if err != nil {
		log.LogError("err: %v", err)
	}
	log.LogInfo("Info %+v", b)

	soc := "vmess1://c7199cd9-964b-4321-9d33-842b6fcec068@qv2ray.net:64338?encryption=none&security=tls&sni=fastgit.org#VMessTCPTLSSNI"
	// soc = "vmess1://75da2e14-4d08-480b-b3cb-0079a0c51275@example.com:443/path?network=http&http.host=example.com%2Cexample1.com&tls=true&tls.allowinsecure=true#VMessTCPTLSSNI%2Cd"
	c, err := explodeKitsunebi(soc)
	if err != nil {
		log.LogError("err: %v", err)
	}
	log.LogInfo("Info %+v", c)

	ss := "ss://c2Fsc2EyMDpwYXNzd29yZA==@34.93.11.120:443/?plugin=v2ray%3bfast-open%3bhost%3dwww.iwuhan.me%3bloglevel%3dnone%3bmode%3dwebsocket%3bmux%3d1%3bpath%3d%2frays%3btls#5%20wss%20%E5%8D%B0%E5%BA%A6%E9%A9%AC%E5%93%88%E6%8B%89%E6%96%BD%E7%89%B9%E6%8B%89%E9%82%A6%E5%AD%9F%E4%B9%B0"
	b, err = parseProxy(ss)
	if err != nil {
		log.LogError("err: %v", err)
	}
	log.LogInfo("Info %+v", b)

	ss = "ss://c2Fsc2EyMDpwYXNzd29yZA==@35.244.126.146:443/?plugin=v2ray%3bfast-open%3bhost%3dwww.iwuhan.me%3bloglevel%3dnone%3bmode%3dwebsocket%3bmux%3d1%3bpath%3d%2frays%3btls#6%20wss%20%E6%BE%B3%E5%A4%A7%E5%88%A9%E4%BA%9A%E6%96%B0%E5%8D%97%E5%A8%81%E5%B0%94%E5%A3%AB%E5%B7%9E%E6%82%89%E5%B0%BC"
	d, err := explodeSS(ss)
	if err != nil {
		log.LogError("err: %v", err)
	}
	log.LogInfo("Info %+v", d)
}
