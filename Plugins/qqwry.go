package Plugins

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/killmonday/fscanx/mylib/stdio/chinese"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
)

var RegEmptyChar = regexp.MustCompile(`\s+`)

const (
	// RedirectMode1 [IP][0x01][国家和地区信息的绝对偏移地址]
	RedirectMode1 = 0x01
	// RedirectMode2 [IP][0x02][信息的绝对偏移][...] or [IP][国家][...]
	RedirectMode2 = 0x02
)

func (r *Reader) Parse(offset uint32) {
	if offset != 0 {
		r.seekAbs(offset)
	}

	switch r.readMode() {
	case RedirectMode1:
		r.readOffset(true)
		r.Parse(0)
	case RedirectMode2:
		r.Result.Country = r.parseRedMode2()
		r.Result.Area = r.readArea()
	default:
		r.seekBack()
		r.Result.Country = r.readString(true)
		r.Result.Area = r.readArea()
	}
}

func (r *Reader) parseRedMode2() string {
	r.readOffset(true)
	str := r.readString(false)
	r.seekBack()
	return str
}

func (r *Reader) readArea() string {
	mode := r.readMode()
	if mode == RedirectMode1 || mode == RedirectMode2 {
		offset := r.readOffset(true)
		if offset == 0 {
			return ""
		}
	} else {
		r.seekBack()
	}
	return r.readString(false)
}

// IPDB common ip database
type IPDB[T ~uint32 | ~uint64] struct {
	Data []byte

	OffLen   uint8
	IPLen    uint8
	IPCnt    T
	IdxStart T
	IdxEnd   T
}

type Reader struct {
	s []byte
	i uint32 // current reading index
	l uint32 // last reading index

	Result Result
}

func NewReader(data []byte) Reader {
	return Reader{s: data, i: 0, l: 0, Result: Result{
		Country: "",
		Area:    "",
	}}
}

func (r *Reader) seekAbs(offset uint32) {
	r.l = r.i
	r.i = offset
}

func (r *Reader) seek(offset int64) {
	r.l = r.i
	r.i = uint32(int64(r.i) + offset)
}

// seekBack: seek to last index, can only call once
func (r *Reader) seekBack() {
	r.i = r.l
}

func (r *Reader) read(length uint32) []byte {
	rs := make([]byte, length)
	copy(rs, r.s[r.i:])
	r.l = r.i
	r.i += length
	return rs
}

func (r *Reader) readMode() (mode byte) {
	mode = r.s[r.i]
	r.l = r.i
	r.i += 1
	return
}

// readOffset: read 3 bytes as uint32 offset
func (r *Reader) readOffset(follow bool) uint32 {
	buf := r.read(3)
	offset := Bytes3ToUint32(buf)
	if follow {
		r.l = r.i
		r.i = offset
	}
	return offset
}

func (r *Reader) readString(seek bool) string {
	length := bytes.IndexByte(r.s[r.i:], 0)
	str := string(r.s[r.i : r.i+uint32(length)])
	if seek {
		r.l = r.i
		r.i += uint32(length) + 1
	}
	return str
}

type Result struct {
	Country string `json:"country"`
	Area    string `json:"area"`
}

func (r *Result) DecodeGBK() *Result {
	r.Country = chinese.ToUTF8(r.Country)
	r.Area = chinese.ToUTF8(r.Area)
	return r
}

func (r *Result) Trim() *Result {
	r.Country = strings.TrimSpace(strings.ReplaceAll(r.Country, "CZ88.NET", ""))
	r.Country = RegEmptyChar.ReplaceAllString(r.Country, "")
	r.Area = strings.TrimSpace(strings.ReplaceAll(r.Area, "CZ88.NET", ""))
	r.Area = RegEmptyChar.ReplaceAllString(r.Area, "")
	return r
}

func (r Result) String() string {
	r.Trim()
	return strings.TrimSpace(fmt.Sprintf("%s|%s", r.Country, r.Area))
}

func Bytes3ToUint32(data []byte) uint32 {
	i := uint32(data[0]) & 0xff
	i |= (uint32(data[1]) << 8) & 0xff00
	i |= (uint32(data[2]) << 16) & 0xff0000
	return i
}

type QQwry struct {
	IPDB[uint32]
}

func (db *IPDB[uint32]) SearchIndexV4(ip uint32) uint32 {
	ipLen := db.IPLen
	entryLen := uint32(db.OffLen + db.IPLen)

	l, r := db.IdxStart, db.IdxEnd
	var ipc, mid uint32
	var buf []byte

	for {
		mid = (r-l)/entryLen/2*entryLen + l
		buf = db.Data[mid : mid+entryLen]
		ipc = uint32(binary.LittleEndian.Uint32(buf[:ipLen]))

		if r-l == entryLen {
			if ip >= uint32(binary.LittleEndian.Uint32(db.Data[r:r+uint32(ipLen)])) {
				buf = db.Data[r : r+entryLen]
			}
			return uint32(Bytes3ToUint32(buf[ipLen:entryLen]))
		}

		if ipc > ip {
			r = mid
		} else if ipc < ip {
			l = mid
		} else if ipc == ip {
			return uint32(Bytes3ToUint32(buf[ipLen:entryLen]))
		}
	}
}

func (db *IPDB[uint64]) SearchIndexV6(ip uint64) uint32 {
	ipLen := db.IPLen
	entryLen := uint64(db.OffLen + db.IPLen)

	buf := make([]byte, entryLen)
	l, r, mid, ipc := db.IdxStart, db.IdxEnd, uint64(0), uint64(0)

	for {
		mid = (r-l)/entryLen/2*entryLen + l
		buf = db.Data[mid : mid+entryLen]
		ipc = uint64(binary.LittleEndian.Uint64(buf[:ipLen]))

		if r-l == entryLen {
			if ip >= uint64(binary.LittleEndian.Uint64(db.Data[r:r+uint64(ipLen)])) {
				buf = db.Data[r : r+entryLen]
			}
			return Bytes3ToUint32(buf[ipLen:entryLen])
		}

		if ipc > ip {
			r = mid
		} else if ipc < ip {
			l = mid
		} else if ipc == ip {
			return Bytes3ToUint32(buf[ipLen:entryLen])
		}
	}
}

// NewQQwry new database from path
func NewQQwry(filePath string) (*QQwry, error) {
	var fileData []byte

	_, err := os.Stat(filePath)
	if err != nil && os.IsNotExist(err) {
		log.Println("path=", filePath)
		log.Println("dat文件不存在")
		return nil, err
	} else {
		fileBase, err := os.OpenFile(filePath, os.O_RDONLY, 0400)
		if err != nil {
			return nil, err
		}
		defer fileBase.Close()

		fileData, err = io.ReadAll(fileBase)
		if err != nil {
			return nil, err
		}
	}

	if !CheckFile(fileData) {
		log.Fatalln("纯真 IP 库存在错误，请重新下载")
	}

	header := fileData[0:8]
	start := binary.LittleEndian.Uint32(header[:4])
	end := binary.LittleEndian.Uint32(header[4:])

	return &QQwry{
		IPDB: IPDB[uint32]{
			Data:     fileData,
			OffLen:   3,
			IPLen:    4,
			IPCnt:    (end-start)/7 + 1,
			IdxStart: start,
			IdxEnd:   end,
		},
	}, nil
}

func (db QQwry) Find(query string, params ...string) (result fmt.Stringer, err error) {
	ip := net.ParseIP(query)
	if ip == nil {
		return nil, errors.New("query should be IPv4")
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("query should be IPv4")
	}
	ip4uint := binary.BigEndian.Uint32(ip4)

	offset := db.SearchIndexV4(ip4uint)
	if offset <= 0 {
		return nil, errors.New("query not valid")
	}

	reader := NewReader(db.Data)
	reader.Parse(offset + 4)
	return reader.Result.DecodeGBK(), nil
}

func (db QQwry) Name() string {
	return "qqwry"
}

func CheckFile(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	header := data[0:8]
	start := binary.LittleEndian.Uint32(header[:4])
	end := binary.LittleEndian.Uint32(header[4:])

	if start >= end || uint32(len(data)) < end+7 {
		return false
	}

	return true
}
