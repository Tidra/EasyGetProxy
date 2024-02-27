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

	router.GET("/clash/proxies", func(web *gin.Context) {
		allProxies := GetProxies("all")
		web.String(200, proxy.ProxiesToClash(allProxies))
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
