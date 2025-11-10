package common

import (
	"github.com/bits-and-blooms/bloom/v3"
	"testing"
)

func TestBloom(t *testing.T) {
	b := bloom.NewWithEstimates(1000000, 0.01)
	b.Add([]byte("Love"))
	b.Add([]byte("Love1"))
	b.Add([]byte("Love2"))
	b.Add([]byte("Love3"))
	b.Add([]byte("Love4"))
	for i := 0; i < 10000; i++ {
		if b.Test([]byte("Love")) {
			t.Log("击中")
		} else {
			t.Log("失败了")
			break
		}
	}
}
