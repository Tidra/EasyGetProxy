package web

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Tidra/EasyGetProxy/unit/config"
	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/proxy"

	"github.com/gin-contrib/cache"
	"github.com/gin-contrib/cache/persistence"
	"github.com/gin-gonic/gin"
)

const version = "v0.0.1"

var router *gin.Engine

func StarWeb() {
	// 初始化路由
	setupRouter()

	port := config.Config.Web.Port
	err := router.Run(":" + port)
	if err != nil {
		log.LogError("router: Web server starting failed. Make sure your port %s has not been used. \n%s", port, err.Error())
	} else {
		log.LogInfo("Proxypool is serving on port: %s", port)
	}
}

func setupRouter() {
	gin.SetMode(gin.ReleaseMode)
	router = gin.New() // 没有任何中间件的路由
	store := persistence.NewInMemoryStore(time.Minute)
	router.Use(gin.Recovery(), cache.SiteCache(store, time.Minute)) // 加上处理panic的中间件，防止遇到panic退出程序

	// TODO: 编写web路由、主页
	temp, err := loadHTMLTemplate() // 加载html模板，模板源存放于html.go中的类似_assetsHtmlSurgeHtml的变量
	if err != nil {
		panic(err)
	}
	router.SetHTMLTemplate(temp) // 应用模板

	router.StaticFile("/static/index.js", "assets/static/index.js")

	router.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "assets/html/index.html", gin.H{
			"domain":               config.Config.Web.Domain,
			"getters_count":        "appcache.GettersCount",
			"all_proxies_count":    "appcache.AllProxiesCount",
			"ss_proxies_count":     "appcache.SSProxiesCount",
			"ssr_proxies_count":    "appcache.SSRProxiesCount",
			"vmess_proxies_count":  "appcache.VmessProxiesCount",
			"trojan_proxies_count": "appcache.TrojanProxiesCount",
			"useful_proxies_count": "appcache.UsefullProxiesCount",
			"last_crawl_time":      "appcache.LastCrawlTime",
			"is_speed_test":        "appcache.IsSpeedTest",
			"version":              version,
		})
	})

	clash := `proxies:
- {"name":"R[ss]-🇬🇧GB_01 | 4.76Mb","server":"jseyu.arvancode.eu.Org","type":"ss","port":443,"password":"Bog0ELmMM9DSxDdQ","cipher":"chacha20-ietf-poly1305"}
- {"name":"R[ss]-🇬🇧GB_02 | 6.09Mb","server":"series-a2-me.samanehha.co","type":"ss","port":443,"password":"Bog0ELmMM9DSxDdQ","cipher":"chacha20-ietf-poly1305"}
- {"name":"[ssr]_03","server":"222.186.20.102","type":"ssr","port":41228,"password":"http://cc.ax/","cipher":"aes-256-cfb","protocol":"auth_aes128_md5","protocol-param":"165400:Hr2aXO","obfs":"plain","obfs-param":"data.bilibili.com/ed5a2165400"}
- {"name":"[trojan]🇦🇪AE_04 | 3.50Mb","server":"139.185.48.248","type":"trojan","country":"🇦🇪AE","port":37902,"password":"46fac810-0332-471a-a074-bdca7824211e","sni":"ua01.bsawc.shop","skip-cert-verify":true,"udp":true}
- {"name":"R[vmess]🇨🇴CO-🇮🇷IR_17 | 4.49Mb","server":"188.114.96.113","type":"vmess","country":"🇨🇴CO","port":80,"uuid":"7022982f-da4c-48c9-c660-b2315abdcf7e","alterId":0,"cipher":"auto","network":"ws","servername":"a.prapt5.ir","http-opts":{},"h2-opts":{},"skip-cert-verify":true,"ws-opts":{"path":"/?ed=2048","headers":{"HOST":"a.prapt5.ir"}}}
- {"name":"[ss]🇩🇪DE_18 | 5.65Mb","server":"80.92.204.106","type":"ss","country":"🇩🇪DE","port":9094,"password":"rpgbNnU9rDDU4aWZ","cipher":"aes-256-cfb"}
- {"name":"R[trojan]🇩🇪DE-🇩🇪DE_19 | 1.33Mb","server":"5.104.108.109","type":"trojan","country":"🇩🇪DE","port":443,"password":"45a8d20d-9a78-4be4-a74a-ab3b9e84e34e","sni":"20-24-33-134.nhost.00cdn.com","skip-cert-verify":true,"udp":true}
- {"name":"R[trojan]🇩🇪DE-🇩🇪DE_20 | 0.27Mb","server":"5.104.108.120","type":"trojan","country":"🇩🇪DE","port":443,"password":"45a8d20d-9a78-4be4-a74a-ab3b9e84e34e","sni":"20-24-33-134.nhost.00cdn.com","skip-cert-verify":true,"udp":true}
- {"name":"R[vmess]🏁 ZZ-🇬🇧GB_58 | 7.34Mb","server":"104.18.202.250","type":"vmess","country":"🏁 ZZ","port":2082,"uuid":"03fcc618-b93d-6796-6aed-8a38c975d581","alterId":0,"cipher":"auto","network":"ws","servername":"erfannewfreenodes.vdmmswyzmzigonvnjk443.workers.dev","http-opts":{},"h2-opts":{},"skip-cert-verify":true,"ws-opts":{"path":"/nina.bond/linkvws","headers":{"HOST":"erfannewfreenodes.vdmmswyzmzigonvnjk443.workers.dev"}}}
`
	e, err := proxy.ExplodeClash(clash)
	router.GET("/clash/proxies", func(web *gin.Context) {
		web.String(200, proxy.ProxiesToClash(e))
	})
}

// 返回页面templates
func loadHTMLTemplate() (t *template.Template, err error) {
	t = template.New("")
	for _, fileName := range AssetNames() { //fileName带有路径前缀
		if strings.Contains(fileName, "css") {
			continue
		}
		data := MustAsset(fileName)                  //读取页面数据
		t, err = t.New(fileName).Parse(string(data)) //生成带路径名称的模板
		if err != nil {
			return nil, err
		}
	}
	return t, nil
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	var _bindata = []string{
		"assets/html/clash-config-local.yaml",
		"assets/html/clash-config.yaml",
		"assets/html/clash.html",
		"assets/html/index.html",
		"assets/html/shadowrocket.html",
		"assets/html/surge.conf",
		"assets/html/surge.html",
		"assets/static/index.js",
	}
	return _bindata
}

func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}
	return a
}

func Asset(name string) ([]byte, error) {
	var _bindata = AssetNames()
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if slices.Contains(_bindata, cannonicalName) {
		parentPath := "D:\\great\\Documents\\EasyGetProxy"
		fullFilePath := filepath.Join(parentPath, cannonicalName)
		contents, err := os.ReadFile(fullFilePath)
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return contents, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}
