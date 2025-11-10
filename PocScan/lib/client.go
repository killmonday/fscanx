package lib

import (
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"github.com/xxx/wscan/common"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	Client           *http.Client
	ClientNoRedirect *http.Client
)

func Inithttp() {
	err := InitHttpClient(common.Proxy, time.Duration(common.WebTimeout)*time.Second)
	if err != nil {
		panic(err)
	}
}

func InitHttpClient(DownProxy string, Timeout time.Duration) error {
	dialTimout := time.Duration(float64(common.WebTimeout) * 0.5 * float64(time.Second)) // 5s
	keepAlive := 1 * time.Second

	dialerCtx := &net.Dialer{
		Timeout:   dialTimout, // tcp 连接的超时时间
		KeepAlive: keepAlive,  // tcp Keep-Alive 的探测间隔时间
	}

	tr := &http.Transport{
		DialContext:         dialerCtx.DialContext, //控制连接的建立时间（含tls握手），不包含后续的数据发送和接收的超时
		MaxConnsPerHost:     1,                     // 每个 host 最大连接数
		MaxIdleConnsPerHost: 1,                     // 每个 host 最大空闲连接数
		MaxIdleConns:        1,                     // 全局空闲连接数限制
		IdleConnTimeout:     keepAlive,             //空闲连接在多长时间后会被关闭
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true},
		TLSHandshakeTimeout: time.Duration(float64(dialTimout) * 0.8), // TLS握手超时 4s

		ResponseHeaderTimeout: time.Duration(float64(common.WebTimeout) * 0.6 * float64(time.Second)), // 设置读取响应头超时 6s
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
	}
	if common.Socks5Proxy != "" {
		dialSocksProxy, err := common.Socks5Dailer(dialerCtx)
		if err != nil {
			return err
		}
		if contextDialer, ok := dialSocksProxy.(proxy.ContextDialer); ok {
			tr.DialContext = contextDialer.DialContext
		} else {
			return errors.New("Failed type assertion to DialContext")
		}
	} else if DownProxy != "" {
		if DownProxy == "1" {
			DownProxy = "http://127.0.0.1:8080"
		} else if DownProxy == "2" {
			DownProxy = "socks5://127.0.0.1:1080"
		} else if !strings.Contains(DownProxy, "://") {
			DownProxy = "http://127.0.0.1:" + DownProxy
		}
		if !strings.HasPrefix(DownProxy, "socks") && !strings.HasPrefix(DownProxy, "http") {
			return errors.New("no support this proxy")
		}
		u, err := url.Parse(DownProxy)
		if err != nil {
			return err
		}
		tr.Proxy = http.ProxyURL(u)
	}

	Client = &http.Client{
		Transport: tr,
		Timeout:   Timeout, //整个HTTP请求的超时，包括连接、请求发送、响应接收
	}
	ClientNoRedirect = &http.Client{
		Transport:     tr,
		Timeout:       Timeout, //整个HTTP请求的超时，包括连接、请求发送、响应接收
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	return nil
}

type Poc struct {
	Name   string  `yaml:"name"`
	Set    StrMap  `yaml:"set"`
	Sets   ListMap `yaml:"sets"`
	Rules  []Rules `yaml:"rules"`
	Groups RuleMap `yaml:"groups"`
	Detail Detail  `yaml:"detail"`
}

type MapSlice = yaml.MapSlice

type StrMap []StrItem
type ListMap []ListItem
type RuleMap []RuleItem

type StrItem struct {
	Key, Value string
}

type ListItem struct {
	Key   string
	Value []string
}

type RuleItem struct {
	Key   string
	Value []Rules
}

func (r *StrMap) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tmp yaml.MapSlice
	if err := unmarshal(&tmp); err != nil {
		return err
	}
	for _, one := range tmp {
		key, value := one.Key.(string), one.Value.(string)
		*r = append(*r, StrItem{key, value})
	}
	return nil
}

//func (r *RuleItem) UnmarshalYAML(unmarshal func(interface{}) error) error {
//	var tmp yaml.MapSlice
//	if err := unmarshal(&tmp); err != nil {
//		return err
//	}
//	//for _,one := range tmp{
//	//	key,value := one.Key.(string),one.Value.(string)
//	//	*r = append(*r,StrItem{key,value})
//	//}
//	return nil
//}

func (r *RuleMap) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tmp1 yaml.MapSlice
	if err := unmarshal(&tmp1); err != nil {
		return err
	}
	var tmp = make(map[string][]Rules)
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	for _, one := range tmp1 {
		key := one.Key.(string)
		value := tmp[key]
		*r = append(*r, RuleItem{key, value})
	}
	return nil
}

func (r *ListMap) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var tmp yaml.MapSlice
	if err := unmarshal(&tmp); err != nil {
		return err
	}
	for _, one := range tmp {
		key := one.Key.(string)
		var value []string
		for _, val := range one.Value.([]interface{}) {
			v := fmt.Sprintf("%v", val)
			value = append(value, v)
		}
		*r = append(*r, ListItem{key, value})
	}
	return nil
}

type Rules struct {
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	Search          string            `yaml:"search"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	Expression      string            `yaml:"expression"`
	Continue        bool              `yaml:"continue"`
}

type Detail struct {
	Author      string   `yaml:"author"`
	Links       []string `yaml:"links"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
}

func LoadMultiPoc(Pocs embed.FS, pocname string) []*Poc {
	var pocs []*Poc
	for _, f := range SelectPoc(Pocs, pocname) {
		if p, err := LoadPoc(f, Pocs); err == nil {
			pocs = append(pocs, p)
		} else {
			fmt.Println("[-] load poc ", f, " error:", err)
		}
	}
	return pocs
}

func LoadPoc(fileName string, Pocs embed.FS) (*Poc, error) {
	p := &Poc{}
	yamlFile, err := Pocs.ReadFile("pocs/" + fileName)

	if err != nil {
		fmt.Printf("[-] load poc %s error1: %v\n", fileName, err)
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, p)
	if err != nil {
		fmt.Printf("[-] load poc %s error2: %v\n", fileName, err)
		return nil, err
	}
	return p, err
}

func SelectPoc(Pocs embed.FS, pocname string) []string {
	entries, err := Pocs.ReadDir("pocs")
	if err != nil {
		fmt.Println(err)
	}
	var foundFiles []string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), pocname) {
			foundFiles = append(foundFiles, entry.Name())
		}
	}
	return foundFiles
}

func LoadPocbyPath(fileName string) (*Poc, error) {
	p := &Poc{}
	data, err := os.ReadFile(fileName)
	if err != nil {
		fmt.Printf("[-] load poc %s error3: %v\n", fileName, err)
		return nil, err
	}
	err = yaml.Unmarshal(data, p)
	if err != nil {
		fmt.Printf("[-] load poc %s error4: %v\n", fileName, err)
		return nil, err
	}
	return p, err
}
