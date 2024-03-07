package main

import (
	"testing"

	"github.com/Tidra/EasyGetProxy/app"
	"github.com/Tidra/EasyGetProxy/web"
)

func Test_main(t *testing.T) {
	// go app.Cron() // 定时运行
	app.CrawlTask()
	app.SpeedCheckTask()
	web.StarWeb()
	web.WebShutdown()
}
