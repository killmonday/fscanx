package simplenet

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"regexp"
	"sync"
	"time"

	"github.com/killmonday/fscanx/common"
)

var RegHttpResp = regexp.MustCompile(`HTTP\/\S+\s+[\d]{3}\s+`)
var BufPool = sync.Pool{
	New: func() any {
		// 预分配 32KB buffer（适中）
		return make([]byte, 16*1024)
	},
}

func init() {

}

func tcpSend(netloc string, data string, duration time.Duration) (string, bool) {
	isOpen := false
	conn, err := common.GetConn("tcp", netloc, duration)
	conn.SetDeadline(time.Now().Add(duration))

	if conn != nil {
		isOpen = true
		defer conn.Close()
	}
	if err != nil {
		return "", isOpen
	}

	// 设置套接字延迟关闭选项，当调用 conn.Close() 时，立即关闭连接，不等待任何未发送或未确认的数据
	if _, ok := conn.(*net.TCPConn); ok {
		err = conn.(*net.TCPConn).SetLinger(0)
		if err != nil {
			fmt.Println("set socket delay close fail:", err)
			return "", isOpen
		}
	}

	_, err = conn.Write([]byte(data))
	if err != nil {
		return "", isOpen
	}
	//读取数据
	buf := BufPool.Get().([]byte)
	defer BufPool.Put(buf)
	n, _ := conn.Read(buf)
	conn.Close()
	return string(buf[:n]), isOpen
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

func tlsSend(netloc string, data string, duration time.Duration) (string, bool) {
	defer func() {
		if r := recover(); r != nil {
			//fmt.Printf("[CRITICAL] tlsSend panic: %v\n", r)
		}
	}()
	isOpen := false
	config := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}

	socksconn, err := common.GetConn("tcp", netloc, duration)
	if err != nil {
		return "", isOpen
	}
	if socksconn != nil {
		defer socksconn.Close()
		isOpen = true
	}
	// 设置套接字延迟关闭选项，当调用 conn.Close() 时，立即关闭连接，不等待任何未发送或未确认的数据
	if _, ok := socksconn.(*net.TCPConn); ok {
		err = socksconn.(*net.TCPConn).SetLinger(0)
		if err != nil {
			fmt.Println("set socket delay close fail:", err)
			return "", isOpen
		}
	}

	conn := tls.Client(socksconn, config)
	if conn != nil {
		defer conn.Close()
	} else {
		return "", isOpen
	}

	err = conn.Handshake()
	if err != nil {
		//fmt.Println("TLS handshake failed: %v", err)
		return "", isOpen
	}

	_, err = io.WriteString(conn, data)
	if err != nil {
		return "", isOpen
	}
	//读取数据
	buf := BufPool.Get().([]byte)
	defer BufPool.Put(buf)
	conn.SetDeadline(time.Now().Add(duration))
	n, _ := conn.Read(buf)
	return string(buf[:n]), isOpen

}

func Send(tls bool, netloc string, data string, duration time.Duration) (string, bool) {
	if tls {
		//return tlsSend(protocol, netloc, data, duration, size)
		return tlsSend(netloc, data, duration)
	} else {
		//return tcpSend(protocol, netloc, data, duration, size)
		return tcpSend(netloc, data, duration)
	}
}
