package getter

import "errors"

var (
	GetterList = make([]Getter, 0)

	ErrorUrlNotFound         = errors.New("url未定义")
	ErrorCrawlSubNotFound    = errors.New("subs爬取节点未定义或格式错误")
	ErrorCreaterNotSupported = errors.New("不支持的获取类型")
)
