package getter

import (
	"errors"
	"sync"

	"github.com/Tidra/EasyGetProxy/unit/config"
	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/proxy"
	"gopkg.in/yaml.v2"
)

// 定义每种getter的基本函数
type Getter interface {
	Get() proxy.ProxyList
	SyncGet(pc chan proxy.Proxy, wg *sync.WaitGroup)
}

// 定义注册getter的初始化函数
type creator func(options map[string]interface{}) (getter Getter, err error)

// 对每一类getter进行字典化,
// registered in package init()
var creatorMap = make(map[string]creator)

func Register(sourceType string, c creator) {
	creatorMap[sourceType] = c
}

func InitGetter() error {
	GetterList = make([]Getter, 0)
	if s := config.Config.SourceFiles; len(s) == 0 {
		return errors.New("未配置信息源")
	} else {
		for _, path := range s {
			data, err := config.ReadFile(path)
			if err != nil {
				log.LogError("初始化信息源配置文件失败: %s\n", err.Error())
				continue
			}

			sourceList := make([]config.Source, 0)
			err = yaml.Unmarshal(data, &sourceList)
			if err != nil {
				log.LogError("初始化信息源配置文件失败: %s\n", err.Error())
				continue
			}

			for _, source := range sourceList {
				if source.Options == nil {
					continue
				}

				c, ok := creatorMap[source.Type]
				if ok {
					g, err := c(source.Options)
					if err == nil && g != nil {
						GetterList = append(GetterList, g)
						log.LogDebug("init getter: %s %v", source.Type, source.Options)
					}
				}
			}
		}
	}
	return nil
}

func StringArray2ProxyArray(origin []string) proxy.ProxyList {
	results := make(proxy.ProxyList, 0)
	for _, link := range origin {
		// log.LogInfo(link)
		p, err := proxy.ParseProxy(link)
		if err == nil && !p.IsEmpty() {
			results = append(results, p)
		}
	}
	return results
}
