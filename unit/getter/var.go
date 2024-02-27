package getter

import "errors"

var (
	GetterList = make([]Getter, 0)

	ErrorUrlNotFound         = errors.New("url未定义")
	ErrorCreaterNotSupported = errors.New("不支持的获取类型")
)
