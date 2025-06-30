package tool

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67"

type HttpClient struct {
	*http.Client
}

var httpClient *HttpClient

func init() {
	httpClient = &HttpClient{http.DefaultClient}
	httpClient.Timeout = time.Second * 10
}

func GetHttpClient() *HttpClient {
	c := *httpClient
	return &c
}

func (c *HttpClient) Get(url string) (resp *http.Response, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6,zh-TW;q=0.5")
	req.Header.Set("User-Agent", UserAgent)
	return c.Do(req)
}

func (c *HttpClient) Post(url string, body io.Reader) (resp *http.Response, err error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6,zh-TW;q=0.5")
	req.Header.Set("User-Agent", UserAgent)
	return c.Do(req)
}

func HttpGetViaProxy(clashProxy C.Proxy, url string, t time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()

	addr, err := urlToMetadata(url)
	if err != nil {
		return nil, err
	}
	conn, err := clashProxy.DialContext(ctx, &addr) // 建立到proxy server的connection，对Proxy的类别做了自适应相当于泛型
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)

	transport := &http.Transport{
		// Note: Dial specifies the dial function for creating unencrypted TCP connections.
		// When httpClient sets this transport, it will use the tcp/udp connection returned from
		// function Dial instead of default tcp/udp connection. It's the key to set custom proxy for http transport
		Dial: func(string, string) (net.Conn, error) {
			return conn, nil
		},
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%d %s to %s", resp.StatusCode, resp.Status, url)
	}

	// read speedtest config file
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func HttpSpeedViaProxy(clashProxy C.Proxy, url string, t time.Duration) (int64, float64, string, error) {
	start := time.Now() //开始时间
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()

	addr, err := urlToMetadata(url)
	if err != nil {
		return -1, -1, "", err
	}
	conn, err := clashProxy.DialContext(ctx, &addr) // 建立到proxy server的connection，对Proxy的类别做了自适应相当于泛型
	if err != nil {
		return -1, -1, "", err
	}
	defer conn.Close()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return -1, -1, "", err
	}
	req = req.WithContext(ctx)

	transport := &http.Transport{
		// Note: Dial specifies the dial function for creating unencrypted TCP connections.
		// When httpClient sets this transport, it will use the tcp/udp connection returned from
		// function Dial instead of default tcp/udp connection. It's the key to set custom proxy for http transport
		Dial: func(string, string) (net.Conn, error) {
			return conn, nil
		},
		// from http.DefaultTransport
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return -1, -1, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return -1, -1, "", fmt.Errorf("%d %s to %s", resp.StatusCode, resp.Status, url)
	}

	ttfb := time.Since(start) // 延迟
	writeSize, _ := io.Copy(io.Discard, resp.Body)
	if writeSize == 0 {
		return -1, -1, "", fmt.Errorf("get %s is none", url)
	}

	downloadTime := time.Since(start) - ttfb
	bandwidth := float64(writeSize) / 1024 / 1024 / downloadTime.Seconds() // mb/s

	return writeSize, bandwidth, ttfb.String(), nil
}

func urlToMetadata(rawURL string) (addr C.Metadata, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			err = fmt.Errorf("%s scheme not Support", rawURL)
			return
		}
	}

	p, _ := strconv.ParseUint(port, 10, 16)

	addr = C.Metadata{
		Host:    u.Hostname(),
		DstPort: uint16(p),
	}
	return
}
