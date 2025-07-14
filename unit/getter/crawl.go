package getter

import (
	"strings"
	"sync"

	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/proxy"
	"github.com/gocolly/colly"
	"github.com/mitchellh/mapstructure"
)

func init() {
	Register("crawl", initCrawlGetter)
}

type Crawl struct {
	Url       string
	Subs      []Sub
	Collector *colly.Collector
	results   proxy.ProxyList
}

type Sub struct {
	Type  string `json:"type" yaml:"type"`
	Xpath string `json:"xpath" yaml:"xpath"`
	Subs  []Sub  `json:"subs" yaml:"subs"`
}

// Get implements Getter.
func (c *Crawl) Get() proxy.ProxyList {
	c.results = make(proxy.ProxyList, 0)

	// 在请求之前打印调试信息
	c.Collector.OnRequest(func(r *colly.Request) {
		log.LogDebug("访问连接: %s", c.Url)
	})

	// 循环构造爬取内容
	for _, s := range c.Subs {
		c.Collector.OnXML(s.Xpath, xmlFunction(c, s))
	}

	err := c.Collector.Visit(c.Url)
	if err != nil {
		log.LogError("%s", err)
	}

	return c.results
}

// SyncGet implements Getter.
func (c *Crawl) SyncGet(pc chan proxy.Proxy, wg *sync.WaitGroup) {
	defer wg.Done()
	nodes := c.Get()
	log.LogInfo("STATISTIC: Crawl\tcount=%d\turl=%s", len(nodes), c.Url)
	for _, node := range nodes {
		pc <- node
	}
}

func xmlFunction(c *Crawl, s Sub) func(x *colly.XMLElement) {
	return func(x *colly.XMLElement) {
		switch s.Type {
		case "url":
			url := x.Attr("href")
			if url == "javascript:;" || url == "#" || url == "" {
				return
			}
			if url[0] == '/' {
				url = c.Url + url
			}
			if s.Subs != nil {
				// log.LogDebug("%v", s.Subs)
				subCollector := c.Collector.Clone()
				// 在请求之前打印调试信息
				subCollector.OnRequest(func(r *colly.Request) {
					log.LogDebug("访问[%s]子连接: %s", c.Url, url)
				})
				// 循环构造爬取内容
				for _, sNew := range s.Subs {
					subCollector.OnXML(sNew.Xpath, xmlFunction(c, sNew))
				}
				err := subCollector.Visit(url)
				if err != nil {
					log.LogError("%s", err)
				}
			}
		case "clash":
			innerHTML := x.Text
			log.LogInfo("Crawl-sub type: %s, path: %s, value: %s", s.Type, s.Xpath, innerHTML)
			// log.LogDebug("%v", c.results)
			c.results = append(c.results, (&Clash{Url: innerHTML}).Get()...)
		case "subscribe":
			innerHTML := x.Text
			log.LogInfo("Crawl-sub type: %s, path: %s, value: %s", s.Type, s.Xpath, innerHTML)
			// log.LogDebug("%v", c.results)
			c.results = append(c.results, (&Subscribe{Url: innerHTML}).Get()...)
		case "fuzzy":
			innerHTML := x.Text
			log.LogInfo("Crawl-sub type: %s, path: %s, value: %s...", s.Type, s.Xpath, innerHTML[0:10])
			nodesString := strings.ReplaceAll(innerHTML, "\t", "")
			nodes := strings.Split(nodesString, "\n")
			c.results = append(c.results, StringArray2ProxyArray(nodes)...)
		}
	}
}

func initCrawlGetter(options map[string]interface{}) (getter Getter, err error) {
	var crawl Crawl
	err = mapstructure.Decode(options, &crawl)
	if err != nil {
		return nil, err
	}

	if crawl.Url == "" {
		return nil, ErrorUrlNotFound
	}
	if crawl.Subs == nil {
		return nil, ErrorCrawlSubNotFound
	}

	crawl.Collector = colly.NewCollector()

	return &crawl, nil
}
