package resources

import (
	"bytes"
	"encoding/json"
	"github.com/chainreactors/utils/encode"
	"github.com/mozillazg/go-pinyin"
	"strings"
)

var pinyinArgs = pinyin.NewArgs()

func UnmarshalData(data []byte, v interface{}) error {
	var err error
	if bytes.HasPrefix(data, []byte{0x1f, 0x8b}) {
		data, err = encode.GzipDecompress(data)
		if err != nil {
			return nil
		}
	}

	return json.Unmarshal(data, &v)
}

// ConvertChineseToPinyin converts Chinese characters to Pinyin.
func ConvertChineseToPinyin(input string) string {
	var s strings.Builder
	for _, i := range input {
		if i >= 0x4e00 && i <= 0x9fa5 {
			if py := pinyin.SinglePinyin(i, pinyinArgs); len(py) > 0 {
				s.WriteString(py[0])
			} else {
				s.WriteRune(i)
			}
		} else {
			s.WriteRune(i)
		}
	}
	return s.String()
}

// NormalizeString performs normalization on the input string.
func NormalizeString(s string) string {
	// Convert Chinese to Pinyin
	s = ConvertChineseToPinyin(s)

	// Convert to lower case
	s = strings.ToLower(s)

	// Replace '-' with '_'
	s = strings.Replace(s, "-", "", -1)

	s = strings.Replace(s, "_", "", -1)

	// Remove spaces
	s = strings.Replace(s, " ", "", -1)

	return s
}
