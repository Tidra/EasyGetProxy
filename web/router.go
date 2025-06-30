package web

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
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

const version = "v0.1.2"

var router *gin.Engine
var srv http.Server

func StarWeb() {
	// 初始化路由
	setupRouter()

	port := config.Config.Web.Port

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	go func() {
		// service connections
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.LogError("监听错误: %s\n", err)
		} else {
			log.LogInfo("网页服务运行在端口: %s", port)
		}
	}()
}

func WebListenStop() {
	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal, 1)
	// kill (no param) default send syscanll.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall. SIGKILL but can"t be catch, so don't need add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.LogInfo("服务关闭中 ...")
	WebShutdown()
}

func WebShutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.LogError("服务关闭失败:", err)
	}
	// catching ctx.Done(). timeout of 5 seconds.
	<-ctx.Done()
	log.LogInfo("服务关闭等待5秒.")
	log.LogInfo("服务已关闭")
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

	router.GET("/", func(web *gin.Context) {
		web.HTML(http.StatusOK, "assets/html/index.html", gin.H{
			"scheme":                  getScheme(web),
			"domain":                  web.Request.Host,
			"getters_count":           app.GettersCount,
			"all_proxies_count":       app.AllProxiesCount,
			"ss_proxies_count":        app.SSProxiesCount,
			"ssr_proxies_count":       app.SSRProxiesCount,
			"vless_proxies_count":     app.VlessProxiesCount,
			"vmess_proxies_count":     app.VmessProxiesCount,
			"trojan_proxies_count":    app.TrojanProxiesCount,
			"hysteria_proxies_count":  app.HysteriaProxiesCount,
			"hysteria2_proxies_count": app.Hysteria2ProxiesCount,
			"snell_proxies_count":     app.SnellProxiesCount,
			"useful_proxies_count":    app.UsefullProxiesCount,
			"last_crawl_time":         app.LastCrawlTime,
			"is_speed_test":           app.IsSpeedTest,
			"version":                 version,
		})
	})

	router.GET("/clash", func(web *gin.Context) {
		web.HTML(http.StatusOK, "assets/html/clash.html", gin.H{
			"scheme":  getScheme(web),
			"domain":  web.Request.Host,
			"version": version,
		})
	})

	router.GET("/shadowrocket", func(web *gin.Context) {
		web.HTML(http.StatusOK, "assets/html/shadowrocket.html", gin.H{
			"scheme":  getScheme(web),
			"domain":  web.Request.Host,
			"version": version,
		})
	})

	router.GET("/surge", func(web *gin.Context) {
		web.HTML(http.StatusOK, "assets/html/surge.html", gin.H{
			"scheme":  getScheme(web),
			"domain":  web.Request.Host,
			"version": version,
		})
	})

	router.GET("/clash/config", func(web *gin.Context) {
		fileType := web.DefaultQuery("f", "")
		proxyTypes := web.DefaultQuery("t", "")
		proxyNotTypes := web.DefaultQuery("nt", "")
		proxyValue := []string{}
		if proxyTypes != "" {
			proxyValue = append(proxyValue, "t="+proxyTypes)
		}
		if proxyNotTypes != "" {
			proxyValue = append(proxyValue, "nt="+proxyNotTypes)
		}

		yamlFile := "assets/html/clash-config.yaml"
		switch fileType {
		case "mihomo":
			yamlFile = "assets/html/clash-config-mihomo.yaml"
			if proxyTypes == "" && proxyNotTypes == "" {
				proxyValue = append(proxyValue, "t=all")
			}
		case "mrs":
			yamlFile = "assets/html/clash-config-mrs.yaml"
			if proxyTypes == "" && proxyNotTypes == "" {
				proxyValue = append(proxyValue, "t=all")
			}
		}

		proxyPreValue := ""
		proxyAfterValue := ""
		if len(proxyValue) > 0 {
			proxyPreValue = "?" + strings.Join(proxyValue, "&")
			proxyAfterValue = strings.Join(proxyValue, "&") + "&"
		}

		web.HTML(http.StatusOK, yamlFile, gin.H{
			"scheme":            getScheme(web),
			"domain":            web.Request.Host,
			"delaydheck_url":    config.Config.HealthCheck.Url,
			"proxy_pre_value":   template.HTML(proxyPreValue),
			"proxy_after_value": template.HTML(proxyAfterValue),
		})
	})

	router.GET("/clash-mrs/config", func(web *gin.Context) {
		yamlFile := "assets/html/clash-config-mrs.yaml"
		web.HTML(http.StatusOK, yamlFile, gin.H{
			"scheme":         getScheme(web),
			"domain":         web.Request.Host,
			"delaydheck_url": config.Config.HealthCheck.Url,
		})
	})

	router.GET("/surge/config", func(web *gin.Context) {
		web.HTML(http.StatusOK, "assets/html/surge.conf", gin.H{
			"scheme": getScheme(web),
			"domain": web.Request.Host,
		})
	})

	router.GET("/clash/proxies", func(web *gin.Context) {
		proxyTypes := web.DefaultQuery("t", "")
		proxyNotTypes := web.DefaultQuery("nt", "")
		proxyCountry := web.DefaultQuery("c", "")
		proxyNotCountry := web.DefaultQuery("nc", "")
		proxySpeed := web.DefaultQuery("s", "")
		proxyOnlyValid := web.DefaultQuery("v", "true")
		text := ""
		if proxyTypes == "" && proxyNotTypes == "" && proxySpeed == "" && proxyCountry == "" && proxyNotCountry == "" && proxyOnlyValid == "true" {
			text = app.GetString("only-clash")
			if text == "" {
				allProxies := app.GetProxies("all")
				proxyNotTypes = "vless,hysteria,hysteria2"
				filterProxies := allProxies.Filter(proxyTypes, proxyNotTypes, proxyCountry, proxyNotCountry, proxySpeed, true)
				text = proxy.ClashToString(filterProxies)
				app.SetString("only-clash", text)
			}
		} else if proxyTypes == "all" && proxyNotTypes == "" && proxySpeed == "" && proxyCountry == "" && proxyNotCountry == "" && proxyOnlyValid == "true" {
			text = app.GetString("all-clash")
			if text == "" {
				allProxies := app.GetProxies("all")
				text = proxy.ClashToString(allProxies)
				app.SetString("all-clash", text)
			}
		} else {
			allProxies := app.GetProxies("all")
			filterProxies := allProxies.Filter(proxyTypes, proxyNotTypes, proxyCountry, proxyNotCountry, proxySpeed, proxyOnlyValid == "true")
			text = proxy.ClashToString(filterProxies)
		}

		web.String(200, text)
	})

	router.GET("/surge/proxies", func(web *gin.Context) {
		proxyTypes := web.DefaultQuery("t", "")
		proxyNotTypes := web.DefaultQuery("nt", "")
		proxyCountry := web.DefaultQuery("c", "")
		proxyNotCountry := web.DefaultQuery("nc", "")
		proxySpeed := web.DefaultQuery("s", "")
		proxyOnlyValid := web.DefaultQuery("v", "true")
		text := ""
		if (proxyTypes == "" || proxyTypes == "all") && proxyNotTypes == "" && proxySpeed == "" && proxyCountry == "" && proxyNotCountry == "" && proxyOnlyValid == "true" {
			text = app.GetString("all-surge")
			if text == "" {
				allProxies := app.GetProxies("all")
				text = proxy.SurgeToString(allProxies)
				app.SetString("all-surge", text)
			}
		} else {
			allProxies := app.GetProxies("all")
			filterProxies := allProxies.Filter(proxyTypes, proxyNotTypes, proxyCountry, proxyNotCountry, proxySpeed, proxyOnlyValid == "true")
			text = proxy.SurgeToString(filterProxies)
		}

		web.String(200, text)
	})

	router.GET("/ss/sub", func(web *gin.Context) {
		proxyTypes := web.DefaultQuery("t", "")
		proxyNotTypes := web.DefaultQuery("nt", "")
		proxyCountry := web.DefaultQuery("c", "")
		proxyNotCountry := web.DefaultQuery("nc", "")
		proxySpeed := web.DefaultQuery("s", "")
		proxyOnlyValid := web.DefaultQuery("v", "true")
		allProxies := app.GetProxies("all")
		filterProxies := allProxies.Filter(proxyTypes, proxyNotTypes, proxyCountry, proxyNotCountry, proxySpeed, proxyOnlyValid == "true")

		web.String(200, proxy.SsToString(filterProxies))
	})

	router.GET("/ssr/sub", func(web *gin.Context) {
		proxyTypes := web.DefaultQuery("t", "")
		proxyNotTypes := web.DefaultQuery("nt", "")
		proxyCountry := web.DefaultQuery("c", "")
		proxyNotCountry := web.DefaultQuery("nc", "")
		proxySpeed := web.DefaultQuery("s", "")
		proxyOnlyValid := web.DefaultQuery("v", "true")
		allProxies := app.GetProxies("all")
		filterProxies := allProxies.Filter(proxyTypes, proxyNotTypes, proxyCountry, proxyNotCountry, proxySpeed, proxyOnlyValid == "true")

		web.String(200, proxy.SsrToString(filterProxies))
	})

	router.GET("/vmess/sub", func(web *gin.Context) {
		proxyTypes := web.DefaultQuery("t", "")
		proxyNotTypes := web.DefaultQuery("nt", "")
		proxyCountry := web.DefaultQuery("c", "")
		proxyNotCountry := web.DefaultQuery("nc", "")
		proxySpeed := web.DefaultQuery("s", "")
		proxyOnlyValid := web.DefaultQuery("v", "true")
		allProxies := app.GetProxies("all")
		filterProxies := allProxies.Filter(proxyTypes, proxyNotTypes, proxyCountry, proxyNotCountry, proxySpeed, proxyOnlyValid == "true")

		web.String(200, proxy.VmessToString(filterProxies))
	})

	router.GET("/trojan/sub", func(web *gin.Context) {
		proxyTypes := web.DefaultQuery("t", "")
		proxyNotTypes := web.DefaultQuery("nt", "")
		proxyCountry := web.DefaultQuery("c", "")
		proxyNotCountry := web.DefaultQuery("nc", "")
		proxySpeed := web.DefaultQuery("s", "")
		proxyOnlyValid := web.DefaultQuery("v", "true")
		allProxies := app.GetProxies("all")
		filterProxies := allProxies.Filter(proxyTypes, proxyNotTypes, proxyCountry, proxyNotCountry, proxySpeed, proxyOnlyValid == "true")
		web.String(200, proxy.TrojanToString(filterProxies))
	})

	router.GET("/v2ray/sub", func(web *gin.Context) {
		proxyTypes := web.DefaultQuery("t", "")
		proxyNotTypes := web.DefaultQuery("nt", "")
		proxyCountry := web.DefaultQuery("c", "")
		proxyNotCountry := web.DefaultQuery("nc", "")
		proxySpeed := web.DefaultQuery("s", "")
		proxyOnlyValid := web.DefaultQuery("v", "true")
		allProxies := app.GetProxies("all")
		filterProxies := allProxies.Filter(proxyTypes, proxyNotTypes, proxyCountry, proxyNotCountry, proxySpeed, proxyOnlyValid == "true")

		web.String(200, proxy.V2rayToString(filterProxies))
	})
}

// getScheme 函数用于获取请求的协议方案，优先检查代理头信息
func getScheme(web *gin.Context) string {
	// 首先检查 X-Forwarded-Proto 请求头
	log.LogInfo("Header: %s %s", web.Request.Header, web.Request.TLS)
	if proto := web.Request.Header.Get("X-Forwarded-Proto"); proto == "https" {
		return "https"
	}
	// 其次检查 X-Real-Proto 请求头（部分场景下可辅助判断）
	if proto := web.Request.Header.Get("X-Real-Proto"); proto == "https" {
		return "https"
	}
	// 其次检查 X-Forwarded-Port 请求头（部分场景下可辅助判断）
	if port := web.Request.Header.Get("X-Forwarded-Port"); port == "443" {
		return "https"
	}
	// 最后检查 TLS 信息
	if web.Request.TLS != nil {
		return "https"
	}
	return "http"
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
		"assets/html/clash-config.yaml",
		"assets/html/clash-config-mihomo.yaml",
		"assets/html/clash-config-mrs.yaml",
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
