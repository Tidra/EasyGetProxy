package getter

import (
	"io"
	"sync"

	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/proxy"
	"github.com/Tidra/EasyGetProxy/unit/tool"
)

func init() {
	Register("clash", initClashGetter)
}

type Clash struct {
	Url string
}

// Get implements Getter.
func (c *Clash) Get() proxy.ProxyList {
	resp, err := tool.GetHttpClient().Get(c.Url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	nodes, err := proxy.ExplodeClash(string(body))
	if err != nil {
		return nil
	} else {
		return nodes
	}
}

// SyncGet implements Getter.
func (c *Clash) SyncGet(pc chan proxy.Proxy, wg *sync.WaitGroup) {
	defer wg.Done()
	nodes := c.Get()
	log.LogInfo("STATISTIC: Clash\tcount=%d\turl=%s", len(nodes), c.Url)
	for _, node := range nodes {
		pc <- node
	}
}

func initClashGetter(options map[string]interface{}) (getter Getter, err error) {
	if url := tool.SafeAsString(options, "url"); url != "" {
		return &Clash{
			Url: url,
		}, nil
	}
	return nil, ErrorUrlNotFound
}
