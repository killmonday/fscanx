package common

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Service指纹检测的Sender抽象
type ServiceSender interface {
	Send(host string, portStr string, data []byte, network string) ([]byte, error)
}

// DefaultServiceSender 默认的ServiceSender实现
type DefaultServiceSender struct {
	timeout time.Duration
}

// NewServiceSender 创建默认的ServiceSender
func NewServiceSender(timeout time.Duration) ServiceSender {
	if timeout <= 0 {
		timeout = 5 * time.Second // 默认5秒超时
	}
	return &DefaultServiceSender{
		timeout: timeout,
	}
}

// Send 实现ServiceSender接口，支持TCP、UDP、TLS协议
func (d *DefaultServiceSender) Send(host string, portStr string, data []byte, network string) ([]byte, error) {
	// 解析端口字符串
	port, actualNetwork := d.parsePortString(portStr, network)
	target := fmt.Sprintf("%s:%d", host, port)

	// 使用解析后的网络协议类型
	switch strings.ToLower(actualNetwork) {
	case "tls", "ssl":
		return d.sendTLS(target, data)
	case "udp":
		return d.sendUDP(target, data)
	case "tcp", "":
		return d.sendTCP(target, data)
	default:
		return d.sendTCP(target, data)
	}
}

// sendTCP 发送TCP数据
func (d *DefaultServiceSender) sendTCP(target string, data []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", target, d.timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送数据
	if len(data) > 0 {
		// 设置写超时
		conn.SetWriteDeadline(time.Now().Add(d.timeout))
		_, err = conn.Write(data)
		if err != nil {
			return nil, err
		}
	}

	// 使用完整的timeout时间，不再强制限制
	readTimeout := d.timeout
	conn.SetReadDeadline(time.Now().Add(readTimeout))

	// 读取响应 - 改进错误处理，即使连接被关闭也要返回已读取的数据
	buffer := make([]byte, 10240)
	n, err := conn.Read(buffer)
	
	// 即使有错误，只要读取到了数据就返回数据
	// 这对于SMB/RDP等协议很重要，它们可能在发送响应后立即关闭连接
	if n > 0 {
		return buffer[:n], nil
	}
	
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}

// sendTLS 发送TLS数据
func (d *DefaultServiceSender) sendTLS(target string, data []byte) ([]byte, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{
		Timeout: d.timeout,
	}, "tcp", target, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送数据
	if len(data) > 0 {
		// 设置写超时
		conn.SetWriteDeadline(time.Now().Add(d.timeout))
		_, err = conn.Write(data)
		if err != nil {
			return nil, err
		}
	}

	// 使用完整的timeout时间，不再强制限制
	readTimeout := d.timeout
	conn.SetReadDeadline(time.Now().Add(readTimeout))

	// 读取响应 - 改进错误处理，即使连接被关闭也要返回已读取的数据
	buffer := make([]byte, 10240)
	n, err := conn.Read(buffer)
	
	// 即使有错误，只要读取到了数据就返回数据
	// 这对于SMB/RDP等协议很重要，它们可能在发送响应后立即关闭连接
	if n > 0 {
		return buffer[:n], nil
	}
	
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}

// sendUDP 发送UDP数据
func (d *DefaultServiceSender) sendUDP(target string, data []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", target, d.timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 发送数据
	if len(data) > 0 {
		// 设置写超时
		conn.SetWriteDeadline(time.Now().Add(d.timeout))
		_, err = conn.Write(data)
		if err != nil {
			return nil, err
		}
	}

	// UDP通常响应更快，设置更短的读超时
	readTimeout := d.timeout
	if readTimeout > 200*time.Millisecond {
		readTimeout = 200 * time.Millisecond // UDP最多等待200ms
	}
	conn.SetReadDeadline(time.Now().Add(readTimeout))

	// 读取响应 - 改进错误处理，即使连接被关闭也要返回已读取的数据
	buffer := make([]byte, 10240)
	n, err := conn.Read(buffer)
	
	// 即使有错误，只要读取到了数据就返回数据
	if n > 0 {
		return buffer[:n], nil
	}
	
	if err != nil {
		return nil, err
	}

	return buffer[:n], nil
}

// parsePortString 解析端口字符串，支持UDP前缀 (U:137)
func (d *DefaultServiceSender) parsePortString(portStr string, defaultNetwork string) (port int, network string) {
	portStr = strings.TrimSpace(portStr)
	network = defaultNetwork // 默认使用传入的网络类型
	
	// 检查UDP标记 (U:139)
	if strings.HasPrefix(strings.ToUpper(portStr), "U:") {
		portStr = portStr[2:] // 移除"U:"前缀
		network = "udp"       // 强制使用UDP
	}
	
	// 解析端口号
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		// 如果解析失败，返回默认端口80
		return 80, network
	}
	
	return portNum, network
}

// Service指纹检测的回调函数
type ServiceCallback func(*ServiceResult)
