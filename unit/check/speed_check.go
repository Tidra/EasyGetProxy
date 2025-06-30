package check

import (
	"io"
	"strings"
	"sync"
	"time"

	"github.com/Tidra/EasyGetProxy/unit/config"
	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/proxy"
	"github.com/Tidra/EasyGetProxy/unit/tool"
	"github.com/ivpusic/grpool"
	"github.com/metacubex/mihomo/adapter"
)

func SpeedCheckAll(proxies proxy.ProxyList) {
	numWorker := config.Config.SpeedTest.MaxConnection
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
	log.LogInfo("[连接速度测试] num: %d, connection: %d, timeout: %ds", len(proxies), numWorker, config.Config.SpeedTest.Timeout)
	// 线程：连接速度检查，检查过程通过grpool的job并发
	for i := range proxies {
		pool.JobQueue <- func(index int) func() {
			return func() {
				defer pool.JobDone()
				if proxies[index].GetCountry() != "" || proxies[index].IsValid() {
					speed, err := ProxySpeedCheck(proxies[index])
					// log.LogDebug(proxies[index].Server, country, err)
					if err == nil && speed > 0 {
						m.Lock()
						proxies[index].SetIsValid(true)
						proxies[index].SetSpeed(speed)
						m.Unlock()
					}
				}

				// Progress status
				dcm.Lock()
				doneCount++
				progress := float64(doneCount * 100 / len(proxies))
				if progress_num < int(progress/10) {
					progress_num = int(progress / 10)
					log.LogInfo("速度检查进度[ %s%s | %5.1f%% ]", strings.Repeat("==", progress_num), strings.Repeat("  ", 10-progress_num), progress)
				}
				dcm.Unlock()
			}
		}(i)
	}

	// 关闭 goroutine 池并等待所有任务完成
	pool.WaitAll()
	pool.Release()
}

func ProxySpeedCheck(p proxy.Proxy) (speedResult float64, err error) {
	pmap := proxy.ProxieToClash(p)
	proxy, err := adapter.ParseProxy(pmap)
	if err != nil {
		return -1, err
	}

	timeout := time.Second * time.Duration(config.Config.SpeedTest.Timeout)
	speedUrl := config.Config.SpeedTest.Url

	var writeSize int64
	var bandwidth float64
	var ttfb string
	for r := 1; r <= maxRetryGet; r++ {
		writeSize, bandwidth, ttfb, err = tool.HttpSpeedViaProxy(proxy, speedUrl, timeout)

		if err == nil {
			break
		} else if r == maxRetryGet {
			return -1, err
		} else if err == io.EOF || strings.Contains(err.Error(), "Connection reset by peer") {
			timeout = timeout + time.Second*10
		}
		time.Sleep(retryInterval)
	}

	log.LogDebug("节点名: %s|带宽: %.2fMB/s(%db)|延迟: %s", proxy.Name(), bandwidth, writeSize, ttfb)

	return bandwidth, nil
}
