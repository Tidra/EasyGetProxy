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

- [x] 提供surge配置文件
- [x] 提供ss、ssr、vmess、sip002订阅
- [x] docker构建

## 安装

### 从源码编译

需要 [安装 Golang](https://golang.org/doc/install) ， 然后拉取代码,

```bash
go get -u -v github.com/Tidra/EasyGetProxy@latest
```

或者，拉取代码的另一种方式 
```
git clone https://github.com/Tidra/EasyGetProxy.git
cd EasyGetProxy
go get
go build
```
then edit `config/config.yaml` and `config/source.yaml` and run it
```
./EasyGetProxy -c ./config/config.yaml
```
或者从源代码运行
```
go run main.go -c ./config/config.yaml
```

## 致谢

- [ssrlive/proxypool](https://github.com/ssrlive/proxypool)
- [tindy2013/subconvertertext](https://github.com/tindy2013/subconverter)

## 声明

本项目遵循 GNU General Public License v3.0 开源，在此基础上，所有使用本项目提供服务者都必须在网站首页保留指向本项目的链接

本项目仅限学习使用，禁止使用本项目进行营利和做其他违法事情，产生的一切后果本项目概不负责