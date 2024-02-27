package main

import (
	"os"
	"sync"
	"testing"

	"github.com/Tidra/EasyGetProxy/unit/config"
	"github.com/Tidra/EasyGetProxy/unit/getter"
	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/proxy"
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

	// 	clash := `proxies:
	// - {"name":"R[ss]-🇬🇧GB_01 | 4.76Mb","server":"jseyu.arvancode.eu.Org","type":"ss","port":443,"password":"Bog0ELmMM9DSxDdQ","cipher":"chacha20-ietf-poly1305"}
	// - {"name":"R[ss]-🇬🇧GB_02 | 6.09Mb","server":"series-a2-me.samanehha.co","type":"ss","port":443,"password":"Bog0ELmMM9DSxDdQ","cipher":"chacha20-ietf-poly1305"}
	// - {"name":"[ssr]_03","server":"222.186.20.102","type":"ssr","port":41228,"password":"http://cc.ax/","cipher":"aes-256-cfb","protocol":"auth_aes128_md5","protocol-param":"165400:Hr2aXO","obfs":"plain","obfs-param":"data.bilibili.com/ed5a2165400"}
	// - {"name":"[trojan]🇦🇪AE_04 | 3.50Mb","server":"139.185.48.248","type":"trojan","country":"🇦🇪AE","port":37902,"password":"46fac810-0332-471a-a074-bdca7824211e","sni":"ua01.bsawc.shop","skip-cert-verify":true,"udp":true}
	// - {"name":"R[vmess]🇨🇴CO-🇮🇷IR_17 | 4.49Mb","server":"188.114.96.113","type":"vmess","country":"🇨🇴CO","port":80,"uuid":"7022982f-da4c-48c9-c660-b2315abdcf7e","alterId":0,"cipher":"auto","network":"ws","servername":"a.prapt5.ir","http-opts":{},"h2-opts":{},"skip-cert-verify":true,"ws-opts":{"path":"/?ed=2048","headers":{"HOST":"a.prapt5.ir"}}}
	// - {"name":"[ss]🇩🇪DE_18 | 5.65Mb","server":"80.92.204.106","type":"ss","country":"🇩🇪DE","port":9094,"password":"rpgbNnU9rDDU4aWZ","cipher":"aes-256-cfb"}
	// - {"name":"R[trojan]🇩🇪DE-🇩🇪DE_19 | 1.33Mb","server":"5.104.108.109","type":"trojan","country":"🇩🇪DE","port":443,"password":"45a8d20d-9a78-4be4-a74a-ab3b9e84e34e","sni":"20-24-33-134.nhost.00cdn.com","skip-cert-verify":true,"udp":true}
	// - {"name":"R[trojan]🇩🇪DE-🇩🇪DE_20 | 0.27Mb","server":"5.104.108.120","type":"trojan","country":"🇩🇪DE","port":443,"password":"45a8d20d-9a78-4be4-a74a-ab3b9e84e34e","sni":"20-24-33-134.nhost.00cdn.com","skip-cert-verify":true,"udp":true}
	// - {"name":"R[vmess]🏁 ZZ-🇬🇧GB_58 | 7.34Mb","server":"104.18.202.250","type":"vmess","country":"🏁 ZZ","port":2082,"uuid":"03fcc618-b93d-6796-6aed-8a38c975d581","alterId":0,"cipher":"auto","network":"ws","servername":"erfannewfreenodes.vdmmswyzmzigonvnjk443.workers.dev","http-opts":{},"h2-opts":{},"skip-cert-verify":true,"ws-opts":{"path":"/nina.bond/linkvws","headers":{"HOST":"erfannewfreenodes.vdmmswyzmzigonvnjk443.workers.dev"}}}
	// `
	// 	e, err := proxy.ExplodeClash(clash)
	// 	if err != nil {
	// 		log.LogError("err: %v", err)
	// 	}
	// 	web.SetProxies("all", e)

	syncGroup := &sync.WaitGroup{}
	var proxysChannel = make(chan proxy.Proxy)
	getter.InitGetter()
	for _, g := range getter.GetterList {
		syncGroup.Add(1)
		go g.SyncGet(proxysChannel, syncGroup)
	}

	proxies := web.GetProxies("all")

	go func() {
		syncGroup.Wait()
		close(proxysChannel)
	}()

	// for 用于阻塞goroutine
	for p := range proxysChannel {
		proxies = proxies.UniqAppendProxy(p)
	}
	web.SetProxies("all", proxies)

	web.StarWeb()
}
