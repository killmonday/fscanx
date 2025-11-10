package Plugins

import (
	"fmt"
	"testing"
)

func TestName(t *testing.T) {
	db, err := NewQQwry("qqwry.dat")
	if err != nil {
		fmt.Println(err)
	}
	res, err := db.Find("211.149.157.245")
	t.Log(res.String())
}
