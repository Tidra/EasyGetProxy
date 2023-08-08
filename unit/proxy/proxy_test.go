package proxy

import (
	"testing"

	"github.com/Tidra/EasyGetProxy/unit/log"
)

func Test(t *testing.T) {
	ssr := "ssr://dHcxLWpxeGguZGRucy5uZXQ6MzIzNjE6YXV0aF9hZXMxMjhfbWQ1OmNoYWNoYTIwOmh0dHBfc2ltcGxlOmFGbHhUMUZsVUEvP29iZnNwYXJhbT1aRzkzYm14dllXUXVkMmx1Wkc5M2MzVndaR0YwWlM1amIyMCZwcm90b3BhcmFtPU5Eb3liRVZyTjNFJnJlbWFya3M9UUZOVFVsUlBUMHhmZEhjeExXcHhlR2d1WkdSdWN5NXVaWFEmZ3JvdXA9VTFOU1ZFOVBUQzVEVDAwZzVvNm82WUNC"
	// ssr = "https://free.dsdog.tk/ss/sub"
	a, err := parseProxy(ssr)
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
}
