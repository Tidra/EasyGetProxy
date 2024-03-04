package main

import (
	"testing"

	"github.com/Tidra/EasyGetProxy/app"
)

func Test_main(t *testing.T) {
	go app.CrawlTask()
	go app.Cron() // 定时运行
	// web.StarWeb()
}
