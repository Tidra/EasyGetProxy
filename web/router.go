package web

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/Tidra/EasyGetProxy/app"
	"github.com/Tidra/EasyGetProxy/unit/config"
	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/proxy"
	"github.com/Tidra/EasyGetProxy/unit/tool"

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
			"getters_count":        app.GettersCount,
			"all_proxies_count":    app.AllProxiesCount,
			"ss_proxies_count":     app.SSProxiesCount,
			"ssr_proxies_count":    app.SSRProxiesCount,
			"vmess_proxies_count":  app.VmessProxiesCount,
			"trojan_proxies_count": app.TrojanProxiesCount,
			"useful_proxies_count": app.UsefullProxiesCount,
			"last_crawl_time":      app.LastCrawlTime,
			"is_speed_test":        app.IsSpeedTest,
			"version":              version,
		})
	})

	router.GET("/clash", func(c *gin.Context) {
		c.HTML(http.StatusOK, "assets/html/clash.html", gin.H{
			"domain": config.Config.Web.Domain,
			"port":   config.Config.Web.Port,
		})
	})

	router.GET("/shadowrocket", func(c *gin.Context) {
		c.HTML(http.StatusOK, "assets/html/shadowrocket.html", gin.H{
			"domain": config.Config.Web.Domain,
		})
	})

	router.GET("/clash/config", func(c *gin.Context) {
		domainUrl := strings.Split(config.Config.Web.Domain, ":")[0]
		c.HTML(http.StatusOK, "assets/html/clash-config.yaml", gin.H{
			"domain":         config.Config.Web.Domain,
			"domain_url":     domainUrl,
			"delaydheck_url": config.Config.HealthCheck.Url,
		})
	})
	router.GET("/clash/localconfig", func(c *gin.Context) {
		c.HTML(http.StatusOK, "assets/html/clash-config-local.yaml", gin.H{
			"domain":         config.Config.Web.Domain,
			"delaydheck_url": config.Config.HealthCheck.Url,
			"port":           config.Config.Web.Port,
		})
	})

	router.GET("/clash/proxies", func(web *gin.Context) {
		proxyTypes := web.DefaultQuery("type", "")
		proxyCountry := web.DefaultQuery("c", "")
		proxyNotCountry := web.DefaultQuery("nc", "")
		text := ""
		if (proxyTypes == "" || proxyTypes == "all") && proxyCountry == "" && proxyNotCountry == "" {
			text = app.GetString("all-clash")
			if text == "" {
				allProxies := app.GetProxies("all")
				text = proxy.ClashToString(allProxies)
				app.SetString("all-clash", text)
			}
		} else {
			allProxies := app.GetProxies("all")
			filterProxies := allProxies.Filter(proxyTypes, proxyCountry, proxyNotCountry)
			text = proxy.ClashToString(filterProxies)
		}

		web.String(200, text)
	})

	router.GET("/ss/sub", func(web *gin.Context) {
		proxyTypes := web.DefaultQuery("type", "")
		proxyCountry := web.DefaultQuery("c", "")
		proxyNotCountry := web.DefaultQuery("nc", "")
		allProxies := app.GetProxies("all")
		filterProxies := allProxies.Filter(proxyTypes, proxyCountry, proxyNotCountry)

		web.String(200, proxy.SsToString(filterProxies, 2))
	})

	router.GET("/sip002/sub", func(web *gin.Context) {
		proxyTypes := web.DefaultQuery("type", "")
		proxyCountry := web.DefaultQuery("c", "")
		proxyNotCountry := web.DefaultQuery("nc", "")
		allProxies := app.GetProxies("all")
		filterProxies := allProxies.Filter(proxyTypes, proxyCountry, proxyNotCountry)

		web.String(200, proxy.SsToString(filterProxies, 1))
	})

	router.GET("/ssr/sub", func(web *gin.Context) {
		proxyTypes := web.DefaultQuery("type", "")
		proxyCountry := web.DefaultQuery("c", "")
		proxyNotCountry := web.DefaultQuery("nc", "")
		allProxies := app.GetProxies("all")
		filterProxies := allProxies.Filter(proxyTypes, proxyCountry, proxyNotCountry)

		web.String(200, proxy.SsrToString(filterProxies))
	})

	router.GET("/vmess/sub", func(web *gin.Context) {
		proxyTypes := web.DefaultQuery("type", "")
		proxyCountry := web.DefaultQuery("c", "")
		proxyNotCountry := web.DefaultQuery("nc", "")
		allProxies := app.GetProxies("all")
		filterProxies := allProxies.Filter(proxyTypes, proxyCountry, proxyNotCountry)

		web.String(200, proxy.VmessToString(filterProxies))
	})

	router.GET("/trojan/sub", func(web *gin.Context) {
		proxyTypes := web.DefaultQuery("type", "")
		proxyCountry := web.DefaultQuery("c", "")
		proxyNotCountry := web.DefaultQuery("nc", "")
		allProxies := app.GetProxies("all")
		filterProxies := allProxies.Filter(proxyTypes, proxyCountry, proxyNotCountry)

		web.String(200, proxy.TrojanToString(filterProxies))
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
	if tool.Contains(_bindata, cannonicalName) {
		contents, err := tool.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return contents, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}
