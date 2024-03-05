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
	Country string  `json:"country,omitempty"`  // 自定义
	Speed   float64 `json:"speed,omitempty"`    // 自定义
	IsAlive bool    `json:"is-alive,omitempty"` // 自定义

	Type   string `json:"type,omitempty"`
	Group  string `json:"group,omitempty"`  // vmess,ssr,ss,socks5,http,trojan,snell
	Name   string `json:"name,omitempty"`   // vmess[ps],ssr,ss,socks5,http,trojan,snell
	Server string `json:"server,omitempty"` // vmess[add],ssr,ss,socks5,http,trojan,snell
	Port   int    `json:"prot,omitempty"`   // vmess,ssr,ss,socks5,http,trojan,snell

	Username         string `json:"user-name,omitempty"`      // *socks5,*http
	Password         string `json:"password,omitempty"`       // *vmess,*ssr,*ss,*socks5,*http,*trojan,*snell: proxy["psk"]
	EncryptMethod    string `json:"cipher,omitempty"`         // *vmess[默认auto],*ssr[默认dummy],*ss
	Plugin           string `json:"plugin,omitempty"`         // *ss
	PluginOption     string `json:"plugin-opts,omitempty"`    // *ss
	Protocol         string `json:"protocol,omitempty"`       // *ssr
	ProtocolParam    string `json:"protocol-param,omitempty"` // *ssr
	OBFS             string `json:"obfs,omitempty"`           // *ssr,snell: proxy["obfs-opts"]["mode"]
	OBFSParam        string `json:"obfs-param,omitempty"`     // *ssr
	UUID             string `json:"uuid,omitempty"`           // *vmess[id]
	AlterID          int    `json:"alterId,omitempty"`        // *vmess
	TransferProtocol string `json:"network,omitempty"`        // *vmess[net=tcp:置空],*trojan[net=tcp:置空]
	FakeType         string `json:"fake-type,omitempty"`      // vmess[type]
	TLSSecure        bool   `json:"tls,omitempty"`            // *vmess[tls],*http,trojan

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
// type PluginOpts struct {
// 	Mode           string `json:"mode"`
// 	Host           string `json:"host,omitempty"`
// 	Tls            bool   `json:"tls,omitempty"`
// 	Path           string `json:"path,omitempty"`
// 	Mux            bool   `json:"mux,omitempty"`
// 	SkipCertVerify bool   `json:"skip-cert-verify,omitempty"`
// }

var (
	SsCiphers  = []string{"rc4-md5", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "bf-cfb", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "salsa20", "chacha20", "chacha20-ietf", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305", "2022-blake3-chacha12-poly1305", "2022-blake3-chacha8-poly1305"}
	SsrCiphers = []string{"none", "table", "rc4", "rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "bf-cfb", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb", "salsa20", "chacha20", "chacha20-ietf"}
)
