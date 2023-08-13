package proxy

func (proxy *Proxy) socksConstruct(group, remarks, server, port, username, password string,
	udp, tfo, scv *bool) {
	proxy.commonConstruct("socks5", group, remarks, server, port, udp, tfo, scv, nil)
	proxy.Username = username
	proxy.Password = password
}
