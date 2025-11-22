package resources

import (
	"fmt"
	"github.com/chainreactors/utils/encode"
	"testing"
)

func TestGzipDecompress(t *testing.T) {
	t.Log("TestGzipDecompress")
	decompress := encode.MustGzipDecompress(EholeData)
	fmt.Println(string(decompress))
}
