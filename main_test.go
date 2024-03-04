package main

import (
	"testing"

	"github.com/Tidra/EasyGetProxy/app"
)

func Test_main(t *testing.T) {
	// go app.Cron() // 定时运行
	app.CrawlTask()
	app.SpeedCheckTask()
	// web.StarWeb()
}
