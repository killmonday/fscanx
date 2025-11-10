package common

// own add
import (
	"time"

	"github.com/juju/ratelimit"
)

var (
	MaxRate    float64 = 1.0 * 1024 * 1024 // 最大速率 字节，此处表示以1MB为基准单位
	PacketSize         = 70                // ICMP 数据包大小，单位字节

	PacketsPerSecond float64
	Bucket_limit     int64
	PacketTime       time.Duration
	Limiter          *ratelimit.Bucket
)
