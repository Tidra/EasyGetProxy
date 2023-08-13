package proxy

func (proxy *Proxy) httpConstruct(group, remarks, server, port, username, password string,
	tls bool, tfo, scv, tls13 *bool) {
	proxyType := "http"
	if tls {
		proxyType = "https"
	}
	proxy.commonConstruct(proxyType, group, remarks, server, port, nil, tfo, scv, tls13)
	proxy.Username = username
	proxy.Password = password
	proxy.TLSSecure = tls
}
