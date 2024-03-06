<h1 align="center">
    <br>EasyGetProxy<br>
</h1>

<h5 align="center">简易的用于获取代理连接池的go程序，包括订阅地址、公开互联网上的ss、ssr、vmess、trojan节点信息</h5>

<p align="center">
    <a href="https://github.com/Tidra">
        <img src="https://img.shields.io/badge/github-Tidra-brightgreen.svg" alt="github">
    </a>
    <a href="https://goreportcard.com/report/github.com/Tidra/EasyGetProxy">
        <img src="https://goreportcard.com/badge/github.com/Tidra/EasyGetProxy?style=flat-square">
    </a>
    <a href="https://github.com/Tidra/EasyGetProxy/blob/main/LICENSE">
        <img alt="GitHub License" src="https://img.shields.io/github/license/Tidra/EasyGetProxy">
    </a>
    <a href="https://goreportcard.com/report/github.com/Tidra/EasyGetProxy">
        <img alt="GitHub Actions Workflow Status" src="https://img.shields.io/github/actions/workflow/status/Tidra/EasyGetProxy/release.yml">
    </a>
    <a href="https://github.com/Tidra/EasyGetProxy/releases">
        <img src="https://img.shields.io/github/release/Tidra/EasyGetProxy/all.svg?style=flat-square">
    </a>
</p>

## 支持

- 支持ss、ssr、vmess、trojan多种类型
- 订阅地址抓取解析
- 公开互联网页面模糊抓取
- 定时抓取自动更新
- 通过配置文件设置抓取源
- 自动检测节点可用性
- 提供clash配置文件

## 待办

- [ ] 从数据库读取缓存信息
- [ ] 增加信息源获取方式
- [x] 提供surge配置文件
- [ ] 更改网页页面
- [ ] snell、vless支持
- [x] 提供ss、ssr、vmess、sip002订阅

## 安装

### 1. 从源码编译

需要 [安装 Golang](https://golang.org/doc/install) ， 然后拉取代码

```bash
go get -u -v github.com/Tidra/EasyGetProxy@latest
```
或者，拉取代码的另一种方式 
```bash
git clone https://github.com/Tidra/EasyGetProxy.git
cd EasyGetProxy
go get
go build
```

修改 `config/config.yaml` 和 `config/source.yaml` 后运行
```bash
./EasyGetProxy -c ./config/config.yaml
```
或者从源代码运行
```bash
go run main.go -c ./config/config.yaml
```

### 2. 下载预编译程序

从 [git releases页下载](https://github.com/Tidra/EasyGetProxy/releases) 预编译程序，需要指定 `config.yaml` 配置文件或者在同目录下创建 `config/config.yaml`

### 3. docker安装

运行下面命令下载 EasyGetProxy 镜像
```bash
docker pull ghcr.io/tidra/easygetproxy:latest
```

下载 `config.yaml` 和 `source.yaml` 到 `${config_path}`
```bash
wget -P ${config_path} https://raw.githubusercontent.com/Tidra/EasyGetProxy/main/config/config.yaml
wget -P ${config_path} https://raw.githubusercontent.com/Tidra/EasyGetProxy/main/config/source.yaml
```
然后运行 EasyGetProxy 即可
```bash
docker run -d --restart=always \
  --name=easygetproxy \
  -p 12580:12580 \
  -v ${config_path}:/config \
  ghcr.io/tidra/easygetproxy:latest \
  -c ${config_path}/config.yaml
```

> 使用 `-p` 参数映射配置文件里的端口  
> 使用 `-v` 参数指定配置文件夹位置（配置文件要自行下载放到目录,方便修改）  
> 使用 `-c` 参数指定配置文件路径，支持http链接

## 使用说明

### 1. 外置参数

目前只保留设置 `配置文件` 参数，可使用以下两种方法设置
1. 直接用 `-c` 调用
```bash
./EasyGetProxy -c ./config/config.yaml
```
2. 配置环境变量
```bash
# 配置在环境变量文件或直接执行
export CONFIG_FILE=${file_path}

# 执行程序
./EasyGetProxy
```

### 2. 配置文件 `config.yaml`

> 配置文件需要为yaml格式文件

配置文件主要如下参数
```yaml
# ======= 留空使用default值  ======= #
# ==== 日志相关 ==== #
log:
  console-level:         # default info
  file-level:            # default no log file
  file-path:             # default log/run.log

# ==== 网页相关 ==== #
web:
  domain: example.com:12580   # or example.com:9443 for reserve proxy server
  port:                       # default 12580

# ==== 代理源配置文件 ==== #
source-files:
  # use local file
  - config/source.yaml
  # use web file
  # - https://example.com/config/source.yaml

# ==== 爬取设置 ==== #
crawl-interval:             # default 60 (minutes)
healthcheck:
  url:                      # default http://www.gstatic.com/generate_204
  timeout:                  # default 5 (seconds)
  max-conn:                 # default 500. The number of health check connections simultaneously

# ==== 测速相关 ==== #
speedtest: 
  is_used: true             # default false. Warning: this will consume large network resources.
  interval:                 # default 720 (min)
  timeout:                  # default 10 (seconds).
  max-conn:                 # default 5. The number of speed test connections simultaneously
```

### 3. 配置源 `source.yaml`

> 信息源文件需要为yaml格式文件

配置可以为:
1. V2ray、SSR、SS、Trojan、clash等订阅链接或文件
2. vmess、ss、ssr、trojan等节点信息
3. 网页中的节点或订阅信息

```yaml
# clash节点信息
- type: clash
  options:
    url: https://xxxxx/xxxx.yaml    # 也可以是文件路径

# 订阅节点
- type: subscribe
  options:
    url: https://xxxxx/xxxx..txt    # 也可以是文件路径

- type: crawl
  options:
    url: https://xxxx.org
    subs: 
      - type: url                  # 子链接
        xpath: //div[2]/h2/a       # 链接对应的xpath
        subs:
          - type: subscribe        # 订阅节点链接
            xpath: //div/p[1]      # 对应的xpath
          - type: clash            # clash订阅链接
            xpath: //div/p[2]      # 对应的xpath
      - type: fuzzy                # 模糊匹配xpath下所有的节点信息，与url同级，所以是https://xxxx.org下的内容
        xpath: //div/div/pre/code  # 对应的xpath
```

## 致谢

- [ssrlive/proxypool](https://github.com/ssrlive/proxypool)
- [tindy2013/subconvertertext](https://github.com/tindy2013/subconverter)

## 声明

本项目遵循 GNU General Public License v3.0 开源，在此基础上，所有使用本项目提供服务者都必须在网站首页保留指向本项目的链接

本项目仅限学习使用，禁止使用本项目进行营利和做其他违法事情，产生的一切后果本项目概不负责