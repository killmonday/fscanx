//go:build !go1.16 || noembed
// +build !go1.16 noembed

package resources

import (
	"encoding/json"
	"github.com/chainreactors/utils"
)

var AliasesData []byte

var PortData []byte // json format
var PrePort *utils.PortPreset

func LoadPorts() error {
	var ports []*utils.PortConfig
	var err error
	err = json.Unmarshal(PortData, &ports)
	if err != nil {
		return err
	}

	PrePort = utils.NewPortPreset(ports)
	return nil
}

// engine
var FingersHTTPData []byte
var FingersSocketData []byte

var GobyData []byte
var Fingerprinthubdata []byte
var EholeData []byte
var WappalyzerData []byte

var CheckSum = map[string]string{}
