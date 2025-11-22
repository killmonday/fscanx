package gonmap

import (
	"fmt"
	"testing"
	"time"
)

func TestScan(t *testing.T) {
	var scanner = New()
	host := "127.0.0.1" // 使用本地地址避免网络问题

	testPorts := []int{22, 80, 138, 135, 3389, 1080, 443, 445, 1521}

	for _, port := range testPorts {
		status, response := scanner.ScanTimeout(host, port, time.Second*3)
		if response != nil && response.FingerPrint != nil {
			fmt.Printf("Port %d: %s - %s\n", port, status, response.FingerPrint.Service)
		} else {
			fmt.Printf("Port %d: %s - no service detected\n", port, status)
		}
	}
}
