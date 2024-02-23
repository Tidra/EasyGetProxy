package main

import (
	"os"
	"testing"

	"github.com/Tidra/EasyGetProxy/unit/config"
	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/web"
)

func Test_main(t *testing.T) {
	var configFilePath = os.Getenv("CONFIG_FILE")
	if configFilePath == "" {
		configFilePath = "config/config.yaml"
	}
	config.SetFilePath(configFilePath)
	config.Parse()

	log.LogInfo("%+v", config.Config)

	web.StarWeb()
}
