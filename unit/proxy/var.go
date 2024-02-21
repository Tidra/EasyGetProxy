package proxy

const (
	SSRServer = iota
	SSRPort
	SSRProtocol
	SSRCipher // ssr的method
	SSROBFS
	SSRSuffix
)

type ProxyList []Proxy

type Proxy struct {
	Type   string `json:"type,omitempty"`
	Group  string `json:"group,omitempty"`  // vmess,ssr,ss,socks5,http,trojan,snell
	Name   string `json:"name,omitempty"`   // vmess[ps],ssr,ss,socks5,http,trojan,snell
	Server string `json:"server,omitempty"` // vmess[add],ssr,ss,socks5,http,trojan,snell
	Port   int    `json:"prot,omitempty"`   // vmess,ssr,ss,socks5,http,trojan,snell

	Username         string      `json:"user-name,omitempty"`      // *socks5,*http
	Password         string      `json:"password,omitempty"`       // *vmess,*ssr,*ss,*socks5,*http,*trojan,*snell: proxy["psk"]
	EncryptMethod    string      `json:"cipher,omitempty"`         // *vmess[默认auto],*ssr[默认dummy],*ss
	Plugin           string      `json:"plugin,omitempty"`         // *ss
	PluginOption     *PluginOpts `json:"plugin-opts,omitempty"`    // *ss
	Protocol         string      `json:"protocol,omitempty"`       // *ssr
	ProtocolParam    string      `json:"protocol-param,omitempty"` // *ssr
	OBFS             string      `json:"obfs,omitempty"`           // *ssr,snell: proxy["obfs-opts"]["mode"]
	OBFSParam        string      `json:"obfs-param,omitempty"`     // *ssr
	UUID             string      `json:"uuid,omitempty"`           // *vmess[id]
	AlterID          uint16      `json:"alterId,omitempty"`        // *vmess
	TransferProtocol string      `json:"network,omitempty"`        // *vmess[net=tcp:置空],*trojan[net=tcp:置空]
	FakeType         string      `json:"fake-type,omitempty"`      // vmess[type]
	TLSSecure        bool        `json:"tls,omitempty"`            // *vmess[tls],*http,trojan

	// *snell: proxy["obfs-opts"]["host"]
	// *trojan: proxy["sni"]
	// *trojan[net=ws]: proxy["ws-opts"]["headers"]["Host"]
	// *vmess[net=ws]: proxy["ws-opts"]["Host"]
	// *vmess[net=http]: proxy["http-opts"]["headers"]["Host"]
	// *vmess[net=h2]: proxy["h2-opts"]["host"]
	// *vmess[net=grpc]: proxy["servername"]
	Host string `json:"Host,omitempty"`

	// *trojan/vmess[net=ws]: proxy["ws-opts"]["path"]
	// *vmess[net=http]: proxy["http-opts"]["path"]
	// *vmess[net=h2]: proxy["h2-opts"]["path"]
	// *trojan/vmess[net=grpc]: proxy["grpc-opts"]["grpc-service-name"]
	Path string `json:"path,omitempty"`

	// *vmess[net=ws]: proxy["ws-opts"]["Edge"]
	// *vmess[net=http]: proxy["http-opts"]["headers"]["Edge"]
	Edge string `json:"Edge,omitempty"`

	QUICSecure string `json:"QUICSecure,omitempty"` // vmess[net=quic]
	QUICSecret string `json:"QUICSecret,omitempty"` // vmess[net=quic]

	UDP            bool `json:"udp,omitempty"`              // *vmess,*ssr,*ss,*socks5,*trojan,*snell
	TCPFastOpen    bool `json:"tfo,omitempty"`              // vmess,ssr,ss,socks5,http,trojan,snell
	SkipCertVerify bool `json:"skip-cert-verify,omitempty"` // *vmess,ssr,ss,*socks5,*http,*trojan,snell
	TLS13          bool `json:"tls13,omitempty"`            // vmess,ss,http,trojan

	SnellVersion any    `json:"version,omitempty"`    // *snell
	ServerName   string `json:"servername,omitempty"` // *vmess
}

// ss的plugin-opts部分
type PluginOpts struct {
	Mode           string `json:"mode"`
	Host           string `json:"host,omitempty"`
	Tls            bool   `json:"tls,omitempty"`
	Path           string `json:"path,omitempty"`
	Mux            bool   `json:"mux,omitempty"`
	SkipCertVerify bool   `json:"skip-cert-verify,omitempty"`
}

type ClashVmess struct {
	Name           string    `json:"name,omitempty"`
	Type           string    `json:"type,omitempty"`
	Server         string    `json:"server,omitempty"`
	Port           any       `json:"port,omitempty"`
	UUID           string    `json:"uuid,omitempty"`
	AlterID        any       `json:"alterId,omitempty"`
	Cipher         string    `json:"cipher,omitempty"`
	TLS            bool      `json:"tls,omitempty"`
	Network        string    `json:"network,omitempty"`
	WSOpts         WSOptions `json:"ws-opts,omitempty"`
	SkipCertVerify bool      `json:"skip-cert-verify,omitempty"`
	UDP            bool      `json:"udp,omitempty"`
}

type WSOptions struct {
	Path                string            `json:"path,omitempty"`
	Headers             map[string]string `json:"headers,omitempty"`
	MaxEarlyData        int               `json:"max-early-data,omitempty"`
	EarlyDataHeaderName string            `json:"early-data-header-name,omitempty"`
}

type ClashSSR struct {
	Name          string `json:"name,omitempty"`
	Type          string `json:"type,omitempty"`
	Server        string `json:"server,omitempty"`
	Port          any    `json:"port,omitempty"`
	Password      string `json:"password,omitempty"`
	Cipher        string `json:"cipher,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	ProtocolParam string `json:"protocol-param,omitempty"`
	OBFS          string `json:"obfs,omitempty"`
	OBFSParam     string `json:"obfs-param,omitempty"`
	UDP           bool   `json:"udp,omitempty"`
}

type ClashSS struct {
	Name       string      `json:"name,omitempty"`
	Type       string      `json:"type,omitempty"`
	Server     string      `json:"server,omitempty"`
	Port       any         `json:"port,omitempty"`
	Password   string      `json:"password,omitempty"`
	Cipher     string      `json:"cipher,omitempty"`
	Plugin     string      `json:"plugin,omitempty"`
	PluginOpts *PluginOpts `json:"plugin-opts,omitempty"`
	UDP        bool        `json:"udp,omitempty"`
}

type ClashHysteria struct {
	Name                string   `yaml:"name"`
	Type                string   `yaml:"type"`
	Server              string   `yaml:"server"`
	Port                int      `yaml:"port"`
	AuthStr             string   `yaml:"auth-str"`
	Obfs                string   `yaml:"obfs"`
	ObfsParams          string   `yaml:"obfs-param"`
	Alpn                []string `yaml:"alpn"`
	Protocol            string   `yaml:"protocol"`
	Up                  string   `yaml:"up"`
	Down                string   `yaml:"down"`
	Sni                 string   `yaml:"sni"`
	SkipCertVerify      bool     `yaml:"skip-cert-verify"`
	RecvWindowConn      int      `yaml:"recv-window-conn"`
	RecvWindow          int      `yaml:"recv-window"`
	Ca                  string   `yaml:"ca"`
	CaStr               string   `yaml:"ca-str"`
	DisableMtuDiscovery bool     `yaml:"disable_mtu_discovery"`
	Fingerprint         string   `yaml:"fingerprint"`
	FastOpen            bool     `yaml:"fast-open"`
}

type ClashTrojan struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Server   string `json:"server"`
	Password string `json:"password"`
	Sni      string `json:"sni,omitempty"`
	Port     any    `json:"port"`
}

type SSD struct {
	Airport      string  `json:"airport"`
	Port         int     `json:"port"`
	Encryption   string  `json:"encryption"`
	Password     string  `json:"password"`
	TrafficUsed  float64 `json:"traffic_used"`
	TrafficTotal float64 `json:"traffic_total"`
	Expiry       string  `json:"expiry"`
	URL          string  `json:"url"`
	Servers      []struct {
		ID            int     `json:"id"`
		Server        string  `json:"server"`
		Ratio         float64 `json:"ratio"`
		Remarks       string  `json:"remarks"`
		Port          string  `json:"port"`
		Encryption    string  `json:"encryption"`
		Password      string  `json:"password"`
		Plugin        string  `json:"plugin"`
		PluginOptions string  `json:"plugin_options"`
	} `json:"servers"`
}

type Clash struct {
	Port      int `yaml:"port"`
	SocksPort int `yaml:"socks-port"`
	// RedirPort          int                      `yaml:"redir-port"`
	// Authentication     []string                 `yaml:"authentication"`
	AllowLan           bool   `yaml:"allow-lan"`
	Mode               string `yaml:"mode"`
	LogLevel           string `yaml:"log-level"`
	ExternalController string `yaml:"external-controller"`
	// ExternalUI         string                   `yaml:"external-ui"`
	// Secret             string                   `yaml:"secret"`
	// Experimental       map[string]interface{} 	`yaml:"experimental"`
	Proxies           []map[string]any `yaml:"proxies"`
	ProxyGroups       []map[string]any `yaml:"proxy-groups"`
	Rule              []string         `yaml:"rules"`
	CFWByPass         []string         `yaml:"cfw-bypass"`
	CFWLatencyTimeout int              `yaml:"cfw-latency-timeout"`

	path       string
	rawProxies []any
	nodeOnly   bool
}
