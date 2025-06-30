package app

var (
	GettersCount = 0

	AllProxiesCount       = 0
	SSRProxiesCount       = 0
	SSProxiesCount        = 0
	VlessProxiesCount     = 0
	VmessProxiesCount     = 0
	TrojanProxiesCount    = 0
	HysteriaProxiesCount  = 0
	Hysteria2ProxiesCount = 0
	SnellProxiesCount     = 0
	UsefullProxiesCount   = 0
	LastCrawlTime         = "程序正在启动，请于3分钟后刷新页面"
	IsSpeedTest           = "未开启"

	SaveCacheInterval    uint64 = 1 // 存入缓存文件间隔时间，单位days
	ClearInvalidInterval uint64 = 3 // 清除无效节点间隔时间，单位days
)
