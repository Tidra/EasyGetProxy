package check

import (
	"encoding/json"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/Dreamacro/clash/adapter"
	"github.com/Tidra/EasyGetProxy/unit/config"
	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/proxy"
	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/ivpusic/grpool"
)

type Data struct {
	Ip       string `json:"ip"`
	Location struct {
		City        string `json:"city"`
		CountryCode string `json:"country_code"`
		CountryName string `json:"country_name"`
		Latitude    string `json:"latitude"`
		Longitude   string `json:"longitude"`
		Province    string `json:"province"`
	} `json:"location"`
}

func LocationCheckAll(proxies proxy.ProxyList) {
	numWorker := config.Config.HealthCheck.MaxConnection
	numJob := 1
	if numWorker > 4 {
		numJob = (numWorker + 2) / 3
	}
	pool := grpool.NewPool(numWorker, numJob)
	pool.WaitCount(len(proxies))

	m := sync.Mutex{}
	dcm := sync.Mutex{}

	doneCount := 0
	progress_num := 0
	log.LogInfo("[归属地检查] num: %d, connection: %d, timeout: %ds", len(proxies), numWorker, config.Config.HealthCheck.Timeout)
	// 线程：归属地检查，检查过程通过grpool的job并发
	for i := range proxies {
		pool.JobQueue <- func(index int) func() {
			return func() {
				defer pool.JobDone()
				country, err := ProxyLocationCheck(proxies[index])
				// log.LogDebug(proxies[index].Server, country, err)
				m.Lock()
				if err == nil && country != "" {
					proxies[index].IsValid = true
					proxies[index].Country = country
				} else if err != nil {
					proxies[index].IsValid = false
				}
				m.Unlock()

				// Progress status
				dcm.Lock()
				doneCount++
				progress := float64(doneCount * 100 / len(proxies))
				if progress_num < int(progress/10) {
					progress_num = int(progress / 10)
					log.LogInfo("归属地检查进度[ %s%s | %5.1f%% ]", strings.Repeat("==", progress_num), strings.Repeat("  ", 10-progress_num), progress)
				}
				dcm.Unlock()
			}
		}(i)
	}

	// 关闭 goroutine 池并等待所有任务完成
	pool.WaitAll()
	pool.Release()
}

func ProxyLocationCheck(p proxy.Proxy) (country string, err error) {
	url := config.Config.LocalCheck.Url
	pmap := proxy.ProxieToClash(p)
	proxy, err := adapter.ParseProxy(pmap)
	if err != nil {
		return "", err
	}

	timeout := time.Second * time.Duration(config.Config.HealthCheck.Timeout)

	var body []byte
	for r := 1; r <= maxRetryGet; r++ {
		body, err = tool.HttpGetViaProxy(proxy, url, timeout)

		if err == nil {
			break
		} else if r == maxRetryGet {
			return "", err
		} else if err == io.EOF || strings.Contains(err.Error(), "timeout") {
			timeout = timeout + time.Second*10
		}
		time.Sleep(retryInterval)
	}

	var data Data
	if err := json.Unmarshal(body, &data); err == nil {
		fieldPath := config.Config.LocalCheck.jsonPath

		// 获取字段值
		fieldValue, err := tool.getFieldByPath(app, fieldPath)
		if err != nil {
			return fieldValue, nil
		}
		return "", err
	} else {
		return "", err
	}
}
