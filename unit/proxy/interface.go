package proxy

// Proxy 定义代理接口
type Proxy interface {
	GetType() string
	GetName() string
	SetName(name string)
	GetOriginName() string
	GetCountry() string
	SetCountry(country string)
	GetSpeed() float64
	SetSpeed(speed float64)
	IsValid() bool
	SetIsValid(isValid bool)
	GetIdentifier() string
	ToString() string // 新增输出节点字符串的方法
}

// ParamToString 定义带参数的 ToString 接口
type ParamToString interface {
	ToStringWithParam(param string) string
}

type ProxyList []Proxy
