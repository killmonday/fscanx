package common

import (
	"errors"
	proxy2 "github.com/xxx/wscan/mylib/proxy"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var GDialer = &net.Dialer{Timeout: 5 * time.Second}
var defaultTcpDuration time.Duration

func initDialer(timeout time.Duration) {
	local_ip := "0.0.0.0"
	if Iface != "" {
		local_ip = Iface
	}
	net_ip := net.ParseIP(local_ip)
	if net_ip == nil {
		net_ip = net.ParseIP("0.0.0.0")
	}
	local_addr := &net.TCPAddr{
		IP: net_ip, // 替换为你想要使用的本地IP地址
	}
	GDialer.Timeout = timeout
	GDialer.LocalAddr = local_addr
	defaultTcpDuration = time.Duration(TcpTimeout)
}

func WrapperTcpWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	defer func() {
		if r := recover(); r != nil {
			LogSuccess("[ERROR] Goroutine WrapperTcpWithTimeout panic: %v\n", r)
		}
	}()
	d := GDialer
	if timeout != defaultTcpDuration {
		d = &net.Dialer{Timeout: timeout}
	}
	return WrapperTCP(network, address, d)
}

func GetProxyDialer() interface{} {
	if Socks5Proxy == "" {
		local_ip := "0.0.0.0"
		if Iface != "" {
			local_ip = Iface
		}
		net_ip := net.ParseIP(local_ip)
		if net_ip == nil {
			net_ip = net.ParseIP("0.0.0.0")
		}
		local_addr := &net.UDPAddr{
			IP: net_ip, // 替换为你想要使用的本地IP地址
		}
		dialer := net.Dialer{Timeout: time.Duration(TcpTimeout) * time.Second, LocalAddr: local_addr}
		return dialer
	} else {
		forward := &net.Dialer{Timeout: time.Duration(TcpTimeout) * time.Second}
		dialer, err := Socks5Dailer(forward)
		if err != nil {
			return nil
		}
		return dialer
	}

}

// WrapperTCP 建立连接返回conn
func WrapperTCP(network, address string, forward *net.Dialer) (net.Conn, error) {
	var conn net.Conn
	// 无代理
	if Socks5Proxy == "" {
		var err error
		if network == "udp" {
			saddr := strings.Split(address, ":")
			targetIP := saddr[0]
			targetPort, _ := strconv.Atoi(saddr[1])
			udpAddr := &net.UDPAddr{
				IP:   net.ParseIP(targetIP),
				Port: targetPort,
			}
			//fmt.Println("[debug] target and port udp: ", targetIP, targetPort)
			socket, err := net.DialUDP("udp", nil, udpAddr)
			if err != nil {
				return nil, err
			}
			socket.SetDeadline(time.Now().Add(time.Duration(TcpTimeout) * time.Second))
			return socket, nil
		}
		conn, err = forward.Dial(network, address)
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			return nil, err
		}
	} else {
		// 有代理
		dailer, err := Socks5Dailer(forward)
		if err != nil {
			return nil, err
		}
		conn, err = dailer.Dial(network, address)
		if err != nil {
			// fmt.Println(err)
			if conn != nil {
				conn.Close()
			}
			return nil, err
		}
	}

	timeout := forward.Timeout
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	return conn, nil

}

func Socks5Dailer(forward *net.Dialer) (proxy2.Dialer, error) {
	u, err := url.Parse(Socks5Proxy)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(u.Scheme) != "socks5" {
		return nil, errors.New("Only support socks5")
	}
	address := u.Host
	var auth proxy2.Auth
	var dailer proxy2.Dialer
	if u.User.String() != "" {
		auth = proxy2.Auth{}
		auth.User = u.User.Username()
		password, _ := u.User.Password()
		auth.Password = password
		dailer, err = proxy2.SOCKS5("tcp", address, &auth, forward)
	} else {
		dailer, err = proxy2.SOCKS5("tcp", address, nil, forward)
	}

	if err != nil {
		return nil, err
	}
	return dailer, nil
}
