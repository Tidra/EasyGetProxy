package config

import (
	"os"

	"github.com/Tidra/EasyGetProxy/unit/log"
	"github.com/Tidra/EasyGetProxy/unit/tool"
	"gopkg.in/yaml.v2"
)

var configFilePath = "config/config.yaml"

type ConfigOptions struct {
	Log struct {
		ConsoleLevel string `json:"console-level" yaml:"console-level"`
		FileLevel    string `json:"file-level" yaml:"file-level"`
		FilePath     string `json:"file-path" yaml:"file-path"`
	} `json:"log" yaml:"log"`

	Web struct {
		Domain string `json:"domain" yaml:"domain"`
		Port   string `json:"port" yaml:"port"`
	}

	SourceFiles   []string `json:"source-files" yaml:"source-files"`
	DatabaseUrl   string   `json:"database-url" yaml:"database-url"`
	TGApiUrl      string   `json:"TG-api-url" yaml:"TG-api-url"`
	CrawlInterval uint64   `json:"crawl-interval" yaml:"crawl-interval"`

	HealthCheck struct {
		Url           string `json:"url" yaml:"url"`
		Timeout       int    `json:"timeout" yaml:"timeout"`
		MaxConnection int    `json:"max-conn" yaml:"max-conn"`
	} `json:"healthcheck" yaml:"healthcheck"`

	SpeedTest struct {
		IsUsed        bool   `json:"is_used" yaml:"is_used"`
		Interval      uint64 `json:"interval" yaml:"interval"`
		Timeout       int    `json:"timeout" yaml:"timeout"`
		MaxConnection int    `json:"max-conn" yaml:"max-conn"`
	} `json:"speedtest" yaml:"speedtest"`
}

// Config 配置
var Config ConfigOptions

func (config ConfigOptions) HostUrl() string {
	if config.Web.Domain == "" {
		return "127.0.0.1:" + config.Web.Port
	} else {
		return config.Web.Domain
	}
}

func SetFilePath(path string) {
	if tool.IsLocalFile(path) {
		path = tool.GetFileFullPath(path)
	}
	configFilePath = path
}

// Parse 解析配置文件，支持本地文件系统和网络链接
func Parse() error {
	fileData, err := tool.ReadFile(configFilePath)
	if err != nil {
		return err
	}
	Config = ConfigOptions{}
	err = yaml.Unmarshal(fileData, &Config)
	if err != nil {
		return err
	}

	// 日志相关默认值以及初始化
	if Config.Log.ConsoleLevel == "" {
		Config.Log.ConsoleLevel = "info"
	}
	log.SetLogLevel(Config.Log.FileLevel, Config.Log.ConsoleLevel)
	if Config.Log.FilePath != "" {
		Config.Log.FilePath = tool.GetFileFullPath(Config.Log.FilePath)
	} else {
		Config.Log.FilePath = tool.GetFileFullPath("log/run.log")
	}
	log.SetLogFilePath(Config.Log.FilePath)

	// 网页相关默认值
	if Config.Web.Port == "" {
		Config.Web.Port = "12580"
	}

	// TG相关默认值
	if Config.TGApiUrl == "" {
		Config.TGApiUrl = "https://rsshub.v2fy.com/telegram/channel/"
	}

	// 爬虫相关默认值
	if Config.CrawlInterval == 0 {
		Config.CrawlInterval = 60
	}

	if Config.HealthCheck.Url == "" {
		Config.HealthCheck.Url = "http://www.google.com/generate_204"
	}
	if Config.HealthCheck.Timeout <= 0 {
		Config.HealthCheck.Timeout = 5
	}
	if Config.HealthCheck.MaxConnection <= 0 {
		Config.HealthCheck.MaxConnection = 500
	}

	if Config.SpeedTest.Interval == 0 {
		Config.SpeedTest.Interval = 720
	}
	if Config.SpeedTest.Timeout <= 0 {
		Config.SpeedTest.Timeout = 10
	}
	if Config.SpeedTest.MaxConnection <= 0 {
		Config.SpeedTest.MaxConnection = 5
	}

	// 部分配置环境变量优先
	if domain := os.Getenv("DOMAIN"); domain != "" {
		Config.Web.Domain = domain
	}

	return nil
}
