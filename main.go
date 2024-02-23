package main

import (
	"os"

	"github.com/Tidra/EasyGetProxy/unit/config"
	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/web"
)

func main() {
	// 设置配置文件并初始化
	var configFilePath = os.Getenv("CONFIG_FILE")
	if configFilePath == "" {
		configFilePath = "config/config.yaml"
	}
	config.SetFilePath(configFilePath)
	config.Parse()

	log.LogInfo("%+v", config.Config)

	web.StarWeb()

}
