package main

import (
	"flag"
	"os"

	"github.com/Tidra/EasyGetProxy/app"
	"github.com/Tidra/EasyGetProxy/unit/config"
	"github.com/Tidra/EasyGetProxy/web"
)

func main() {
	// 定义配置文件
	var configFilePath = os.Getenv("CONFIG_FILE")

	flag.StringVar(&configFilePath, "c", "", "path to config file: config.yaml")
	flag.Parse()
	if configFilePath == "" {
		configFilePath = "config/config.yaml"
	}
	config.SetConfigFilePath(configFilePath)

	go app.CrawlTask() // 首次初始化所有信息
	go app.Cron()      // 定时运行
	web.StarWeb()

}
