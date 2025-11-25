package common

import (
	"errors"
	proxy2 "github.com/killmonday/fscanx/mylib/proxy"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var GDialer = &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 1 * time.Second}
var defaultTcpDuration time.Duration
var IsValidSocks5 bool = true
var bufPool = sync.Pool{
	New: func() any {
		return make([]byte, 2)
	},
}
var httpProbe = []byte("GET / HTTP/1.0\r\n\r\n")

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
	defaultTcpDuration = time.Duration(TcpTimeout) * time.Second

	//test socks5
	if Socks5Proxy != "" {
		invalidAddr := "255.255.255.255:65531"
		conn, _ := GetConn("tcp4", invalidAddr, defaultTcpDuration)
		if conn != nil {
			IsValidSocks5 = false
			defer conn.Close()
		}
	}
}

func GetConn(network, address string, timeout time.Duration) (net.Conn, error) {
	defer func() {
		if r := recover(); r != nil {
			LogSuccess("[ERROR] Goroutine GetConn panic: %v\n", r)
		}
	}()
	if timeout == GDialer.Timeout {
		return WrapperTCP(network, address, GDialer)
	} else {
		Dialer := &net.Dialer{Timeout: timeout, KeepAlive: 1 * time.Second}
		return WrapperTCP(network, address, Dialer)
	}
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
func WrapperTCP(network, address string, dia *net.Dialer) (net.Conn, error) {
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
			socket.SetDeadline(time.Now().Add(dia.Timeout))
			return socket, nil
		}
		conn, err = dia.Dial(network, address)
		if err != nil {
			if conn != nil {
				conn.Close()
			}
			return nil, err
		}
	} else {
		// 有代理
		dailer, err := Socks5Dailer(dia)
		if err != nil {
			return nil, err
		}
		conn, err = dailer.Dial(network, address)
		if err != nil {
			//fmt.Println(err)
			if conn != nil {
				conn.Close()
			}
			return nil, err
		}
		// 如果是不标准的socks5服务，并且没有使用gonmap探测，那么这里会发送http探针，并尝试读取，从而判断目标端口是否真的开放。
		// 如果是有效的socks5服务，则不需要这一步。如果使用了gonmap探测，也不需要这一步，从NotMatch响应/Open响应+IsValidSocks5可以判断是不是真的开放，NotMatch表示有响应内容只是不匹配任何指纹
		if IsValidSocks5 == false && UseNmap == false {
			conn.SetDeadline(time.Now().Add(dia.Timeout))
			//发送http请求来测试目标主机+端口是否有响应，在这种socks5代理下，socks5 server并不是最终与目标直接建立连接的机器，没有按照标准socks5 rfc进行响应，无法通过conn来判断目标端口是否开放
			_, err = conn.Write(httpProbe)
			if err != nil {
				if conn != nil {
					conn.Close()
				}
				return nil, err
			}
			buf := bufPool.Get().([]byte)
			defer bufPool.Put(buf)
			//尝试读取
			_, err = conn.Read(buf)
			if err != nil {
				if conn != nil {
					conn.Close()
				}
				return nil, err
			}
			//目标端口真的开放。重新建立一个新连接并返回
			conn.Close()
			conn, err = dailer.Dial(network, address)
			if err != nil {
				if conn != nil {
					conn.Close()
				}
				return nil, err
			}
		}

	}

	if err := conn.SetWriteDeadline(time.Now().Add(dia.Timeout)); err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(dia.Timeout)); err != nil {
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
