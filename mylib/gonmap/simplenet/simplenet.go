package simplenet

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/xxx/wscan/mylib/socks"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/xxx/wscan/common"
)

var RegHttpResp = regexp.MustCompile(`HTTP\/\S+\s+[\d]{3}\s+`)

func tcpSend(protocol string, netloc string, data string, duration time.Duration, size int) (string, error) {
	protocol = strings.ToLower(protocol)
	//fmt.Println("[debug]   tcpSend 1")
	conn, err := common.WrapperTcpWithTimeout(protocol, netloc, duration)
	//fmt.Println("[debug]   tcpSend 2，", conn, err)
	if conn != nil {
		defer conn.Close()
	}
	if err != nil {
		return "", errors.New(err.Error() + ", connect fail")
	}
	//fmt.Println("[debug]   tcpSend 2.5")

	// 设置套接字延迟关闭选项，当调用 conn.Close() 时，立即关闭连接，不等待任何未发送或未确认的数据
	if _, ok := conn.(*net.TCPConn); ok {
		//fmt.Println("[debug] tcpSend 2.6")

		err = conn.(*net.TCPConn).SetLinger(0)
		//fmt.Println("[debug] tcpSend 2.7")

		if err != nil {
			fmt.Println("set socket delay close fail:", err)
			return "", err
		}
	}
	//fmt.Println("[debug] tcpSend 3")

	//err = conn.(*net.TCPConn).SetLinger(0)
	//if err != nil {
	//	fmt.Println("设置套接字延迟关闭选项失败:", err)
	//	return "", err
	//}

	// local_ip := "0.0.0.0"
	// if common.Iface != "" {
	// 	local_ip = common.Iface
	// }
	// net_ip := net.ParseIP(local_ip)
	// if net_ip == nil {
	// 	net_ip = net.ParseIP("0.0.0.0")
	// }
	// local_addr := &net.TCPAddr{
	// 	IP: net_ip, // 替换为你想要使用的本地IP地址
	// }
	// var conn net.Conn
	// var err error
	// d := &net.Dialer{Timeout: duration, LocalAddr: local_addr}
	// if common.Socks5Proxy != "" {
	// 	dailer, err := common.Socks5Dailer(d)
	// 	if err != nil {
	// 		return "", err
	// 	}
	// 	conn, err = dailer.Dial(protocol, netloc)
	// 	if err != nil {
	// 		return "", err
	// 	}
	// } else {
	// 	conn, err = d.Dial(protocol, netloc)
	// 	if err != nil {
	// 		return "", err
	// 	}
	// }

	//old
	// conn, err := net.DialTimeout(protocol, netloc, duration)
	// if err != nil {
	// 	//fmt.Println(conn)
	// 	return "", errors.New(err.Error() + " STEP1:CONNECT")
	// }

	_, err = conn.Write([]byte(data))
	//fmt.Println("[debug] tcpSend 4")

	conn.SetDeadline(time.Now().Add(time.Duration(common.TcpTimeout) * time.Second))
	//fmt.Println("[debug] tcpSend 5")

	//fmt.Println("[debug] send :", data, "sendto:", conn.RemoteAddr().String())
	if err != nil {
		return "", errors.New(err.Error() + " STEP2:WRITE")
	}
	//读取数据
	var buf []byte              // big buffer
	var tmp = make([]byte, 256) // using small tmo buffer for demonstrating
	var length int
	is_first_read := true
	//HTTP\/\S+\s+[\d][\d][\d]\s+
	for {
		if uConn, ok := conn.(*net.UDPConn); ok {
			//fmt.Println("[debug] udp conn, reading")
			length, _, err = uConn.ReadFrom(tmp)
		} else if uConn, ok := conn.(*socks.UDPConnSocks5); ok {
			length, _, err = uConn.ReadFrom(tmp)
		} else {
			length, err = conn.Read(tmp)
		}
		if err != nil {
			//fmt.Println(err)
			return "", err
		}
		buf = append(buf, tmp[:length]...)
		if is_first_read {
			match := RegHttpResp.FindSubmatch(tmp)
			if len(match) > 0 {
				break
			}
			is_first_read = false
		}
		if length < len(tmp) {
			break
		}
		if err != nil {
			//fmt.Println(err)
			break
		}
		if len(buf) > size {
			break
		}
	}
	conn.Close()

	if err != nil { //&& err != io.EOF
		return "", errors.New(err.Error() + " STEP3:READ")
	}

	if len(buf) == 0 {
		return "", errors.New("STEP3:response is empty")
	}

	return string(buf), nil
}

// 打印单个证书信息
func printCertificate(cert *x509.Certificate) string {
	//fmt.Printf("  Subject: %s\n", cert.Subject)
	//fmt.Printf("  Issuer: %s\n", cert.Issuer)
	//fmt.Printf("  Valid From: %s\n", cert.NotBefore)
	//fmt.Printf("  Valid To: %s\n", cert.NotAfter)
	//fmt.Printf("  DNS Names: %v\n", cert.DNSNames)
	//info := fmt.Sprintf("wadbm[Cert: _subject:%s; _issuer:%s]\n", cert.Subject, cert.Issuer)
	info := fmt.Sprintf("wadbm[Cert: %s]\n", cert.Subject)
	return info
}

func tlsSend(protocol string, netloc string, data string, duration time.Duration, size int) (string, error) {
	defer func() {
		if r := recover(); r != nil {
			//fmt.Printf("[CRITICAL] tlsSend panic: %v\n", r)
		}
	}()

	protocol = strings.ToLower(protocol)
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}
	// dialer := &net.Dialer{
	// 	Timeout:  duration,
	// 	Deadline: time.Now().Add(duration * 2),
	// }

	// conn, err := tls.DialWithDialer(dialer, protocol, netloc, config)
	// if err != nil {
	// 	return "", errors.New(err.Error() + " STEP1:CONNECT")
	// }

	socksconn, err := common.WrapperTcpWithTimeout(protocol, netloc, duration)
	if err != nil {
		return "", errors.New(err.Error() + " connect fail")
	}
	if socksconn != nil {
		defer socksconn.Close()
	}
	conn := tls.Client(socksconn, config)
	if conn != nil {
		defer conn.Close()
	} else {
		return "", errors.New("tls connect fail")
	}

	err = conn.Handshake()
	if err != nil {
		//fmt.Println("TLS handshake failed: %v", err)
		return "", err
	}

	_, err = io.WriteString(conn, data)
	//fmt.Println("[debug] wirte:", data, "\n==============================")
	if err != nil {
		return "", errors.New(err.Error() + " STEP2:WRITE")
	}
	//读取数据
	var buf []byte              // big buffer
	var tmp = make([]byte, 256) // using small tmo buffer for demonstrating
	var length int
	is_first_read := true
	conn.SetDeadline(time.Now().Add(time.Duration(common.TcpTimeout) * time.Second))
	for {
		//设置读取超时Deadline
		// _ = conn.SetReadDeadline(time.Now().Add(time.Second * 3))
		length, err = conn.Read(tmp)
		buf = append(buf, tmp[:length]...)

		if is_first_read {
			match := RegHttpResp.FindSubmatch(tmp)
			if len(match) > 0 {
				break
			}
			is_first_read = false
		}

		if length < len(tmp) {
			break
		}
		if err != nil {
			break
		}
		if len(buf) > size {
			break
		}
	}
	if err != nil { //&& err != io.EOF
		return "", errors.New(err.Error() + " STEP3:READ")
	}
	if len(buf) == 0 {
		return "", errors.New("STEP3:response is empty")
	}
	return string(buf), nil
}

func Send(protocol string, tls bool, netloc string, data string, duration time.Duration, size int) (string, error) {
	if tls {
		return tlsSend(protocol, netloc, data, duration, size)
	} else {
		return tcpSend(protocol, netloc, data, duration, size)
	}
}
