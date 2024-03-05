package getter

import (
	"strings"
	"sync"

	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/proxy"
	"github.com/Tidra/EasyGetProxy/unit/tool"
)

func init() {
	Register("subscribe", initSubscribeGetter)
}

type Subscribe struct {
	Url string
}

// Get implements Getter.
func (s *Subscribe) Get() proxy.ProxyList {
	// 支持链接以及本地文件
	body, err := tool.ReadFile(s.Url)
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
func (v *Subscribe) SyncGet(pc chan proxy.Proxy, wg *sync.WaitGroup) {
	defer wg.Done()
	nodes := v.Get()
	log.LogInfo("STATISTIC: Subscribe\tcount=%d\turl=%s", len(nodes), v.Url)
	for _, node := range nodes {
		pc <- node
	}
}

func initSubscribeGetter(options map[string]interface{}) (getter Getter, err error) {
	if url := tool.SafeAsString(options, "url"); url != "" {
		return &Subscribe{
			Url: url,
		}, nil
	}
	return nil, ErrorUrlNotFound
}
