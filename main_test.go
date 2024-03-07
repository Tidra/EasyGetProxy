package main

import (
	"testing"

	"github.com/Tidra/EasyGetProxy/web"
)

func Test_main(t *testing.T) {
	mainInit()
	web.StarWeb()
	web.WebShutdown()
}
