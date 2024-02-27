package getter

import (
	"io"
	"strings"
	"sync"

	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/proxy"
	"github.com/Tidra/EasyGetProxy/unit/tool"
)

func init() {
	Register("sub", initSubGetter)
}

type Sub struct {
	Url string
}

// Get implements Getter.
func (s *Sub) Get() proxy.ProxyList {
	resp, err := tool.GetHttpClient().Get(s.Url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	nodesString, err := tool.Base64DecodeString(string(body))
	if err != nil {
		return nil
	}
	nodesString = strings.ReplaceAll(nodesString, "\t", "")
	nodes := strings.Split(nodesString, "\n")

	return StringArray2ProxyArray(nodes)
}

// SyncGet implements Getter.
func (v *Sub) SyncGet(pc chan proxy.Proxy, wg *sync.WaitGroup) {
	defer wg.Done()
	nodes := v.Get()
	log.LogInfo("STATISTIC: Sub\tcount=%d\turl=%s", len(nodes), v.Url)
	for _, node := range nodes {
		pc <- node
	}
}

func initSubGetter(options map[string]interface{}) (getter Getter, err error) {
	if url := tool.SafeAsString(options, "url"); url != "" {
		return &Sub{
			Url: url,
		}, nil
	}
	return nil, ErrorUrlNotFound
}
