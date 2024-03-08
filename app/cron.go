package app

import (
	"os"
	"sync"
	"time"

	"github.com/Tidra/EasyGetProxy/unit/check"
	"github.com/Tidra/EasyGetProxy/unit/config"
	"github.com/Tidra/EasyGetProxy/unit/getter"
	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/proxy"
	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/jasonlvhit/gocron"
)

var cacheFile = "assets/all-clash.dat"

func Cron() {
	_ = gocron.Every(config.Config.CrawlInterval).Minutes().Do(CrawlTask)
	_ = gocron.Every(config.Config.SpeedTest.Interval).Minutes().Do(SpeedCheckTask)
	_ = gocron.Every(SaveCacheInterval).Days().Do(SaveCacheToFileTask)
	_ = gocron.Every(ClearInvalidInterval).Days().Do(clearInvalidProxy)
	<-gocron.Start()
}

func CrawlTask() {
	config.Parse()
	log.LogInfo("%+v", config.Config)

	syncGroup := &sync.WaitGroup{}
	var proxysChannel = make(chan proxy.Proxy)
	getter.InitGetter()
	for _, g := range getter.GetterList {
		syncGroup.Add(1)
		go g.SyncGet(proxysChannel, syncGroup)
	}

	proxies := GetProxies("all")
	if cacheData, err := tool.ReadFile(cacheFile); err == nil {
		if cacheProxies, err := proxy.ExplodeClash(string(cacheData)); err == nil {
			log.LogInfo("读取缓存文件[%s]节点数: %d", cacheFile, len(cacheProxies))
			proxies.UniqAppendProxys(cacheProxies)
		}
	}

	go func() {
		syncGroup.Wait()
		close(proxysChannel)
	}()

	// for 用于阻塞goroutine
	for p := range proxysChannel {
		proxies.UniqAppendProxy(p)
	}

	check.LocationCheckAll(proxies)
	proxies = proxies.RenameAll()

	GettersCount = len(getter.GetterList)
	AllProxiesCount, UsefullProxiesCount, SSRProxiesCount, SSProxiesCount, VmessProxiesCount, TrojanProxiesCount = proxies.Count()

	location, err := time.LoadLocation("Asia/Shanghai") //设置时区
	if err != nil {
		// 修复window获取不到时区问题
		location = time.FixedZone("CST", 8*3600)
	}
	LastCrawlTime = time.Now().In(location).Format("2006-01-02 15:04:05")
	log.LogInfo("节点总数: %d", AllProxiesCount)
	log.LogInfo("有效节点数: %d", UsefullProxiesCount)
	log.LogInfo("SSR节点数: %d", SSRProxiesCount)
	log.LogInfo("SS节点数: %d", SSProxiesCount)
	log.LogInfo("Vmess节点数: %d", VmessProxiesCount)
	log.LogInfo("Trojan节点数: %d", TrojanProxiesCount)

	SetProxies("all", proxies)
	SetString("all-clash", proxy.ClashToString(proxies))
	SetString("all-surge", proxy.SurgeToString(proxies))
}

func SpeedCheckTask() {
	proxies := GetProxies("all")
	if config.Config.SpeedTest.IsUsed {
		IsSpeedTest = "已开启"
		check.SpeedCheckAll(proxies)
		proxies = proxies.RenameAll()
		SetProxies("all", proxies)
		SetString("all-clash", proxy.ClashToString(proxies))
		SetString("all-surge", proxy.SurgeToString(proxies))
	} else {
		IsSpeedTest = "未开启"
	}
}

func SaveCacheToFileTask() {
	proxiesText := GetString("all-clash")
	// 打开文件，如果文件不存在则创建，如果存在则截断
	file, err := os.Create(cacheFile)
	if err != nil {
		log.LogError("创建缓存文件失败: %s", err.Error())
		return
	}
	defer file.Close()

	// 将数据写入文件
	_, err = file.WriteString(proxiesText)
	if err != nil {
		log.LogError("写入缓存文件失败: %s", err.Error())
		return
	}

	log.LogInfo("写入缓存文件成功.")
}

func clearInvalidProxy() {
	proxies := GetProxies("all")
	filterProxies := proxies.Filter("", "", "")
	SetProxies("all", filterProxies)
}
