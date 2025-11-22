package Plugins

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/killmonday/fscanx/PocScan"
	"github.com/killmonday/fscanx/PocScan/lib"
	"github.com/killmonday/fscanx/common"
	fingers "github.com/killmonday/fscanx/mylib/finger"
	"github.com/killmonday/fscanx/mylib/stdio/chinese"
	"golang.org/x/net/html"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

var (
	regTitle       = regexp.MustCompile("(?ims)<title.*?>(.*?)</title>")
	regDirectInJS  = regexp.MustCompile(`(?i)location\.href\s*=\s*['"]([^'"]+)['"]`)
	regDirectInJS2 = regexp.MustCompile(`(?i)window\.navigate\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	regDirectInJS3 = regexp.MustCompile(`(?i)window\.location\.replace\s*\(\s*['"]([^'"]+)['"]\s*\)`)
	regDirectInJS4 = regexp.MustCompile(`(?i)self\.location\s*=\s*['"]([^'"]+)['"]`)
	regDirectInJS5 = regexp.MustCompile(`(?i)top\.location\s*=\s*['"]([^'"]+)['"]`)
	regCopyRight   = regexp.MustCompile(`(?i)(.*)(©|&copy;|版权所有)(.*)`)
)

var Engine *fingers.Engine
var use_engine = []string{"fingers", "goby"} // fingers fingerprinthub wappalyzer ehole goby

func init() {
	// 创建finger引擎实例
	engineNew, err := fingers.NewEngine(use_engine...)
	if err != nil {
		fmt.Printf("Failed to create engine: %v\n", err)
		os.Exit(1)
	}
	Engine = engineNew
}

type stringer interface {
	String() string
}

var BufPool = sync.Pool{
	New: func() any {
		// 最大长度 192KB buffer
		return make([]byte, 192*1024)
	},
}

var BufBuildPool = sync.Pool{
	New: func() any {
		return &bytes.Buffer{}
	},
}

func ExtractTitleAndICP(htmlBytes []byte) (title string, icp string, copyright string, jumpUrl string) {
	// 从html字节流中提取 标题 和 ICP 备案号（基于html.Tokenizer）
	z := html.NewTokenizer(bytes.NewReader(htmlBytes))
	var inTitle bool
	var inScript bool
	var titleFound bool
	var jumpUrlFound bool
	var titleBuf strings.Builder
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			err := z.Err()
			if err == io.EOF {
				// 正常结束
				return
			}
			return
		}

		// 如果两个都找到了，提前终止，不再继续解析
		if title != "" && icp != "" && copyright != "" {
			return
		}

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			token := z.Token()
			tagName := token.Data // 如 "title"

			if !titleFound && strings.EqualFold(tagName, "title") {
				inTitle = true
				titleBuf.Reset() // 准备接收 title 文本
			} else if string(tagName) == "script" {
				inScript = true
			}

		case html.EndTagToken:
			token := z.Token()
			tagName := token.Data

			if !titleFound && strings.EqualFold(tagName, "title") {
				inTitle = false
				// 标题结束，提取已拼接的内容。还要做html实体转换，有一些标题全是html实体
				title = titleBuf.String()
				title = strings.ReplaceAll(title, "\n", "")
			}
			if inScript {
				inScript = false
			}

		case html.TextToken:
			//读取到可显文字
			text := strings.TrimSpace(string(z.Text()))
			text = chinese.ToUTF8(html.UnescapeString(text)) // 检测是中文编码才会转

			if text == "" {
				continue
			}
			if inTitle && text != "" {
				// 正在 title 标签内
				titleBuf.WriteString(text) // 检测是中文编码才会转utf-8
			}
			if !jumpUrlFound && inScript && text != "" {
				// 正在 script 标签内
				temp := getJSRedirectURL(z.Text())
				if temp != "" {
					jumpUrl = temp
					jumpUrlFound = true

				}
			}
			// 无论是否在 title 中，都尝试从当前文本节点中匹配 ICP 备案号
			if icp == "" && text != "" {
				if candidate := extractFirstICP(text); candidate != "" {
					icp = candidate
				}
			}
			// 版权信息
			match := regCopyRight.FindString(text)
			if match != "" {
				copyright = match
			}

		}
	}

}

func extractFirstICP(text string) string {
	// extractFirstICP 从一段文本中提取第一个看起来像 ICP 备案号的字符串
	// 支持如：京ICP备12345678号、沪ICP证000001号-1 等
	keywords := []string{"ICP备", "ICP证"} // 常见关键词，通常备案号中带有 "ICP备" 或 "ICP证"

	for _, kw := range keywords {
		idx := strings.Index(text, kw)
		if idx == -1 {
			continue
		}
		// 从 kw 开始，尝试提取后续的数字和“号”
		var rest string
		if idx-3 >= 0 {
			rest = text[idx-3:]
		} else {
			rest = text[idx:]
		}

		// 提取包含 kw 的连续片段，通常备案号格式比较规范
		candidate := extractICPCandidate(rest)
		if candidate != "" {
			return candidate
		}
	}

	return ""
}

func isChineseCharacter(s string) bool {
	// 将字符串的第一个字符转换为 rune 类型
	runeValue := []rune(s)[0]
	// 判断该字符是否属于中文字符范围
	return runeValue >= '\u4e00' && runeValue <= '\u9fa5'
}

func extractICPCandidate(s string) string {
	// 从疑似ICP备案号的text中提取icp
	// 启发式规则：找到 ICP备/ICP证 后，取后面 10~20 字符，通常包含数字和“号”
	start := strings.Index(s, "ICP")
	if start == -1 {
		return ""
	}
	// 从 ICP 开始，往后最多取 30 个字符，通常备案号不会太长
	end := start + 30
	if end > len(s) {
		end = len(s)
	}
	candidate := s[start:end]

	// 简单校验：是否含有数字和“号”字（常见于备案号结尾）
	if !strings.ContainsAny(candidate, "0123456789") {
		return ""
	}
	if !strings.Contains(candidate, "号") {
		return ""
	}

	// 做一个简单合理长度校验：ICP备+数字+号，总长度通常 10~20。这里是计算比较utf8字符串长度
	if utf8.RuneCountInString(candidate) < 10 || utf8.RuneCountInString(candidate) > 30 {
		return ""
	}

	// 正则匹配
	icpRegex := regexp.MustCompile(`(ICP备|ICP证)\d+[号\-]\d*号?`)
	matches := icpRegex.FindString(candidate)
	if matches != "" {
		if start-3 >= 0 {
			area := s[start-3 : start] //utf-8中，常见的中文占用3个字节
			if isChineseCharacter(area) {
				// 如果ICP前面是中文，大概率就是地区号
				return s[start-3:start] + matches
			}
		}
		return matches
	}
	if index := strings.Index(candidate, "ICP备案号："); index != -1 {
		if len(candidate) >= index+15 {
			return candidate[index+15:]
		}
		return candidate
	} else if index = strings.Index(candidate, "ICP备案号:"); index != -1 {
		if len(candidate) >= index+13 {
			return candidate[index+13:]
		}
		return candidate
	}
	return candidate
}

func WebScanController(targetInfo *common.HostInfo) error {
	common.WebScanRateCtrlCh <- struct{}{} // web探测任务的并发控制
	defer func() {
		<-common.WebScanRateCtrlCh
	}()
	if common.Scantype == "webpoc" {
		//仅PoC扫描。用户设置扫描类型是poc扫描，仅做poc扫描
		PocScan.PocScan(targetInfo)
		return nil
	}
	err := WebScanWorker(targetInfo) // web扫描

	if common.IsCheckPoc && err == nil {
		//用户启用了poc扫描（-poc），所以做完了web扫描就接着做poc扫描
		PocScan.PocScan(targetInfo)
	} else {
		// errlog := fmt.Sprintf("[-] WebScanController %v %v", targetInfo.Url, err)
		// common.LogError(errlog)
	}

	return err
}

func WebScanWorker(targetInfo *common.HostInfo) (err error) {
	//处理url并调用web扫描逻辑、web跳转控制及扫描等
	if targetInfo.Url == "" {
		// 如果url为空，说明输入是ip，此处构造url
		switch targetInfo.Ports {
		case "80":
			targetInfo.Url = fmt.Sprintf("http://%s", targetInfo.Host)
		case "443":
			targetInfo.Url = fmt.Sprintf("https://%s", targetInfo.Host)
		default:
			host := fmt.Sprintf("%s:%s", targetInfo.Host, targetInfo.Ports)
			protocol := IdentifyProtocol(host, common.TcpTimeout)
			targetInfo.Url = fmt.Sprintf("%s://%s:%s", protocol, targetInfo.Host, targetInfo.Ports)
		}
	} else {
		// url存在，说明输入的是域名资产，检查格式是否符合标准url，不符合就构造一下。否则不做任何操作
		if !strings.Contains(targetInfo.Url, "://") {
			host := strings.Split(targetInfo.Url, "/")[0]                     // 取出 host部分 拿去检测协议
			protocol := IdentifyProtocol(host, common.TcpTimeout)             //探测检查是http还是https
			targetInfo.Url = fmt.Sprintf("%s://%s", protocol, targetInfo.Url) //组装url
		}
	}
	// 发送http请求，识别web产品
	err, reurl := DoWebScan(targetInfo, 1, "")
	if err != nil {
		return err
	}
	// 如果reurl是https，判断原始url是否就是https，如果不是则用https协议探测一遍
	if reurl == "https" {
		targetInfo.Url = strings.Replace(targetInfo.Url, "http://", "https://", 1)
		err, reurl = DoWebScan(targetInfo, 1, "")
		//还有跳转
		if strings.Contains(reurl, "://") {
			firstUrl := targetInfo.Url
			targetInfo.Url = reurl
			err, _ = DoWebScan(targetInfo, 3, firstUrl)
			if err != nil {
				return
			}
		}
	} else {
		//有url跳转
		if strings.Contains(reurl, "://") {
			firstUrl := targetInfo.Url
			targetInfo.Url = reurl
			err, _ = DoWebScan(targetInfo, 3, firstUrl)
			if err != nil {
				return err
			}
		}
	}
	targetInfo = nil
	return err
}

func parseCertField(value interface{}) string {
	var certByte = strings.Builder{}
	t := reflect.TypeOf(value)
	v := reflect.ValueOf(value)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
		v = v.Elem()
	}

	for i := 0; i < t.NumField(); i++ {
		// 从0开始获取Student所包含的key
		key := t.Field(i)
		// 通过interface方法来获取key所对应的值
		value := v.Field(i).Interface()
		var cell string
		switch s := value.(type) {
		case string:
			cell = s
		case []string:
			cell = strings.Join(s, "; ")
		case int:
			cell = strconv.Itoa(s)
		case stringer:
			cell = s.String()
		}
		if cell == "" {
			continue
		}
		certByte.WriteString(key.Name)
		certByte.WriteString(": ")
		certByte.WriteString(cell)
		certByte.WriteString("\r\n")
	}
	return certByte.String()
}

func GetCertRaw(TLS *tls.ConnectionState) string {
	if TLS == nil {
		return ""
	}
	if len(TLS.PeerCertificates) == 0 {
		return ""
	}
	var certByte strings.Builder
	cert := TLS.PeerCertificates[0]
	certByte.WriteString(parseCertField(cert))
	certByte.WriteString("\r\n")
	certByte.WriteString("SUBJECT:\r\n")
	certByte.WriteString(parseCertField(cert.Subject))
	certByte.WriteString("\r\n")
	certByte.WriteString("Issuer:\r\n")
	certByte.WriteString(parseCertField(cert.Issuer))

	return certByte.String()
}

func DoWebScan(targetInfo *common.HostInfo, scanType int, firstUrl string) (error, string) {
	//scanType 1 初次访问，不进行跳转
	//scanType 2 获取图标 /favicon.ico
	//scanType 3 访问一些跳转的URL，例如从初次访问得到的302、location等
	//scanType 4 初次访问响应400 -> 使用https重新扫描
	var client *http.Client
	var title string
	copyRight, icp, certInfo := "", "", ""
	var reurl string //提取到的跳转url
	var serverIp string

	req, err := http.NewRequest("GET", targetInfo.Url, nil)
	if err != nil {
		return err, ""
	}
	req.Header.Set("User-agent", common.UserAgent)
	req.Header.Set("Accept", common.Accept)
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,en;q=0.8,zh;q=0.7,*")
	if common.Cookie != "" {
		req.Header.Set("Cookie", common.Cookie)
	}
	req.Header.Set("Connection", "close")
	// 创建Trace对象收集连接信息
	trace := &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			addr := connInfo.Conn.RemoteAddr().String()
			if strings.HasPrefix(addr, "[") == false {
				index := strings.Index(addr, ":")
				serverIp = addr[:index]
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	if scanType == 1 {
		client = lib.ClientNoRedirect
	} else {
		client = lib.Client
	}
	client.Timeout = time.Duration(common.WebTimeout) * time.Second
	// 发送请求
	resp, err := client.Do(req)
	if resp != nil {
		defer func() {
			resp.Body.Close()
			req.Close = true
		}()
	}
	if err != nil {
		if !strings.HasPrefix(targetInfo.Url, "https") {
			return err, "https" //如果报错，用https协议来重新探测一次
		}
		return err, ""
	}
	defer func() {
		resp.Body.Close()
		req.Close = true
	}()

	body, err := ReadRawWithSize(resp, 192*1024) // 最大获取前64KB页面
	if err != nil {
		//fmt.Println("[-] read body err:", err)
	}

	// 如果是https网站，获取证书信息
	if len(targetInfo.Url) >= 5 && targetInfo.Url[:5] == "https" {
		var certStr = strings.Builder{}
		certInfo = GetCertRaw(resp.TLS)
		subject := ""
		domainStr := "Domain="
		issuser := "Issuser="
		if certInfo != "" {
			// 提取subject
			if index := strings.Index(certInfo, "Subject"); index != -1 {
				if len(certInfo) >= index+9 {
					tmp := certInfo[index+9:]
					endIndex := strings.Index(tmp, "\r\n")
					if endIndex != -1 {
						subject += tmp[:endIndex]
					}
				}

			}
			// 提取域名
			if index := strings.Index(certInfo, "DNSNames"); index != -1 {
				tmp := certInfo[index+10:]
				endIndex := strings.Index(tmp, "\r\n")
				if endIndex != -1 {
					domainStr += tmp[:endIndex]
				}
			}

			// 提取颁发者信息
			if index := strings.Index(certInfo, "Issuer"); index != -1 {
				tmp := certInfo[index+9:]
				endIndex := strings.Index(tmp, "\r\n")
				if endIndex != -1 {
					issuser += tmp[:endIndex]
				}
			}
			var isFirst bool = true
			if len(subject) > 0 {
				certStr.WriteString(subject)
				isFirst = false
			}
			if len(domainStr) > 7 {
				if isFirst {
					certStr.WriteString(domainStr)
					isFirst = false
				} else {
					certStr.WriteString("," + domainStr)
				}
			}
			if len(issuser) > 8 {
				if isFirst {
					certStr.WriteString(issuser)
					isFirst = false
				} else {
					certStr.WriteString("," + issuser)
				}
			}

			certInfo = strings.ReplaceAll(certStr.String(), "\n", "_")
			certInfo = strings.ReplaceAll(certInfo, "\r", "_")
			/*
				cert_info content like this:

				SignatureAlgorithm: SHA256-RSA
				PublicKeyAlgorithm: RSA
				Version: 3
				SerialNumber: 4183520561172206966195670189914676379
				Issuer: CN=TrustAsia TLS RSA CA,OU=Domain Validated SSL,O=TrustAsia Technologies\, Inc.,C=CN
				Subject: CN=hbsd.top
				NotBefore: 2023-06-19 00:00:00 +0000 UTC
				NotAfter: 2024-06-18 23:59:59 +0000 UTC
				MaxPathLen: -1
				OCSPServer: http://statuse.digitalcertvalidation.com
				IssuingCertificateURL: http://cacerts.digitalcertvalidation.com/TrustAsiaTLSRSACA.crt
				DNSNames: hbsd.top; www.hbsd.top
			*/
		}
	}
	// 提取标题、备案号、版权信息
	title, icp, copyRight, reurl = ExtractTitleAndICP(body)
	if title == "" || strings.TrimSpace(title) == "" {
		title = "None"
	}
	if reurl != "" && !strings.Contains(reurl, "http") {
		// 解析 原始URL，准备组装跳转url
		parsedURL, err := url.Parse(targetInfo.Url)
		if err == nil {
			// 提取协议、主机名和端口（如果有）
			baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
			reurl = baseURL + "/" + reurl
		}
	}
	if copyRight != "" {
		copyRight = strings.Replace(copyRight, "版权所有", "", 1)
		copyRight = strings.Replace(copyRight, "Copyright", "", 1)
		copyRight = strings.Replace(copyRight, "：", "", 1)
		copyRight = strings.ReplaceAll(copyRight, "All Rights Reserved", "")
		copyRight = strings.Replace(copyRight, "备案号", "", 1)
		copyRight = strings.ReplaceAll(copyRight, "[", "")
		copyRight = strings.ReplaceAll(copyRight, "]", "")
		copyRight = strings.Replace(copyRight, "漏", "_", 1)
		if len(copyRight) > 69 {
			copyRight = copyRight[:69]
		}
	}
	//如果是初次扫描/跳转url扫描：进行资产识别、标题提取、跳转url提取等
	if scanType != 2 {
		if reurl == "" {
			redirURL, err1 := resp.Location() // 通过http头部location尝试获取跳转
			if err1 == nil {
				reurl = redirURL.String()
				if reurl == targetInfo.Url { // || reurl == Url+"/" ，加了 / 有些时候确实页面不同
					reurl = ""
				}
			}
		}
	}

	// 检测web指纹
	frames, err := Engine.DetectContent(body)
	products := frames.String()

	// 处理web识别的结果
	result := strings.Builder{}
	productSlice := strings.Split(products, "||")
	result.WriteString("[+] Product ")
	result.WriteString(fmt.Sprintf("%s\t%d\t(%s)\t", targetInfo.Url, resp.StatusCode, title))
	firstWriteFlag := false
	if products != "" && len(productSlice) >= 1 {
		result.WriteString(strings.Join(productSlice, ", "))
		firstWriteFlag = true
	}
	if certInfo != "" {
		if firstWriteFlag {
			result.WriteString(", [Cert:")
		} else {
			result.WriteString("[Cert:")
			firstWriteFlag = true
		}
		result.WriteString(certInfo)
		result.WriteString("]")
	}
	if firstUrl != "" {
		if scanType != 1 {
			if firstWriteFlag {
				result.WriteString(", [From:")
			} else {
				result.WriteString("[From:")
				firstWriteFlag = true
			}
			result.WriteString(firstUrl)
			result.WriteString("]")
		}

	}
	if icp != "" {
		if firstWriteFlag {
			result.WriteString(", [ICP:")
		} else {
			result.WriteString("[ICP:")
			firstWriteFlag = true
		}
		result.WriteString(icp)
		result.WriteString("]")
	}
	if copyRight != "" {
		if firstWriteFlag {
			result.WriteString(", [copyright:")
		} else {
			result.WriteString("[copyright:")
			firstWriteFlag = true
		}
		result.WriteString(copyRight)
		result.WriteString("]")
	}
	if serverIp != "" {
		if strings.HasPrefix(targetInfo.Url[7:], serverIp) || strings.HasPrefix(targetInfo.Url[8:], serverIp) {
		} else {
			if firstWriteFlag {
				result.WriteString(", [IP:")
			} else {
				result.WriteString("[IP:")
				firstWriteFlag = true
			}
			result.WriteString(serverIp)
			result.WriteString("]")
		}
		if Czdb != nil {
			ipInfo, err := Czdb.Find(serverIp)
			if err == nil {
				infoStr := ipInfo.String()
				if len(infoStr) != 0 && strings.HasPrefix(infoStr, "IANA|") == false {
					if firstWriteFlag {
						result.WriteString(", [L:")
					} else {
						result.WriteString("[L:")
						firstWriteFlag = true
					}
					result.WriteString(ipInfo.String())
					result.WriteString("]")
				}
			}
		}
	}

	result.WriteString("\r\n")
	common.LogSuccess(result.String())

	if reurl != "" {
		return nil, reurl
	}
	if resp.StatusCode == 400 && !strings.HasPrefix(targetInfo.Url, "https") {
		return nil, "https"
	}
	return nil, ""
}

// TimeoutReader 是一个包装了 io.Reader 的结构体，用于支持超时控制
type TimeoutReader struct {
	Reader io.Reader
	Ctx    context.Context
}

// Read 实现了 io.Reader 接口，并支持超时控制
func (tr *TimeoutReader) Read(p []byte) (n int, err error) {
	select {
	case <-tr.Ctx.Done(): // 如果超时，返回错误
		return 0, tr.Ctx.Err()
	default:
		return tr.Reader.Read(p)
	}
}

// 读取原始响应体，包括header+body
func ReadRawWithSize(resp *http.Response, size int64) ([]byte, error) {
	defer resp.Body.Close()
	//var raw bytes.Buffer
	raw := BufBuildPool.Get().(*bytes.Buffer)
	defer raw.Reset()
	defer BufBuildPool.Put(raw)

	// http响应状态行
	//raw.WriteString(fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status))
	raw.WriteString(resp.Proto)
	raw.WriteString(" ")
	raw.WriteString(resp.Status)
	raw.WriteString("\r\n")

	// 响应头
	for k, v := range resp.Header {
		for _, val := range v {
			//raw.WriteString(fmt.Sprintf("%s: %s\r\n", k, val))
			raw.WriteString(k)
			raw.WriteString(": ")
			raw.WriteString(val)
			raw.WriteString("\r\n")
		}
	}
	raw.WriteString("\r\n") // header-body 分隔符

	// Body（仅前 size 字节）
	buf := BufPool.Get().([]byte)
	defer BufPool.Put(buf)

	// 创建带有超时控制的 context
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(common.WebTimeout)*time.Second)
	defer cancel()

	limitedReader := io.LimitReader(resp.Body, size)
	timeoutReader := &TimeoutReader{
		Reader: limitedReader,
		Ctx:    ctx,
	}
	n, err := io.ReadFull(timeoutReader, buf)

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		err = nil // io.ErrUnexpectedEOF说明body 小于 192KB，如果是这个error则忽略
	} else if err != nil {
		return raw.Bytes(), err
	}

	raw.Write(buf[:n])

	// 如果启用了http keep-alive，且body未读完，则继续读取（丢弃）剩余的部分，这是为了能复用http连接，否则检测到body未读完会直接弃用该连接
	//if resp.Close == false {
	//	_, _ = io.Copy(io.Discard, resp.Body)
	//}

	// 返回完整的响应数据
	return raw.Bytes(), nil
}

//new bufpool
//func ReadRawWithSize(resp *http.Response, size int64) ([]byte, error) {
//	buf := BufPool.Get().([]byte)
//	defer BufPool.Put(buf)
//
//	////读取协议头部分
//	//raw.WriteString(resp.Proto + " " + resp.Status + "\r\n")
//	//raw.Write(ReadHeader(resp))
//	//
//	////读取header属性部分
//	//for k, v := range resp.Header {
//	//	for _, i := range v {
//	//		header.WriteString(k + ": " + i + "\r\n")
//	//	}
//	//}
//
//	n, err := io.ReadFull(resp.Body, buf)
//	if err != nil {
//		// io.ErrUnexpectedEOF 说明 body 小于 16KB，可以直接copy一份副本返回
//		if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
//			return append([]byte(nil), buf[:n]...), nil
//		}
//		return nil, err
//	}
//
//	// Body 大于 16KB，销毁剩余部分，这部分是为了能复用http连接，这里不需要也可以，因为已经关闭了http的keepalive
//	_, _ = io.Copy(io.Discard, resp.Body)
//
//	// copy返回一份副本，不要使用pool里的buf，因为将会被其他协程复用
//	return append([]byte(nil), buf[:n]...), nil
//}

// new bufpool
//func NewReadBodyWithSize(resp *http.Response, size int64) ([]byte, error) {
//	buffer := BufPool.Get().(*bytes.Buffer)
//	buffer.Reset()
//	defer BufPool.Put(buffer)
//	defer resp.Body.Close()
//
//	if size > 0 {
//		buffer.Grow(int(size))
//	}
//
//	_, err := io.Copy(buffer, resp.Body)
//	if err != nil && err != io.EOF {
//		return nil, err
//	}
//
//	temp := buffer.Bytes()
//	length := len(temp)
//	var body []byte
//
//	// 避免过多浪费（>50%）
//	if cap(temp) > length*3/2 {
//		body = make([]byte, length)
//		copy(body, temp)
//	} else {
//		body = append([]byte(nil), temp...) // 防止后续修改
//	}
//	return body, nil
//}

//func NewReadBodyWithSize(resp *http.Response, size int64) ([]byte, error) {
//	//ioutil.ReadAll starts at a very small 512
//	//it really should let you specify an initial size
//	buffer := bytes.NewBuffer(make([]byte, 0, 65536))
//	//io.Copy(buffer, resp.Body)
//	writeN, err := io.CopyN(buffer, resp.Body, size)
//	if err != nil {
//		return buffer.Bytes(), err
//	}
//	temp := buffer.Bytes()
//	length := int(writeN)
//	var body []byte
//	//are we wasting more than 10% space?
//	if cap(temp) > (length + length/10) {
//		body = make([]byte, length)
//		copy(body, temp)
//	} else {
//		body = temp
//	}
//	return body, err
//}

//func NewReadBodyWithSize(resp *http.Response, size int64) ([]byte, error) {
//	//ioutil.ReadAll starts at a very small 512
//	//it really should let you specify an initial size
//	buffer := bytes.NewBuffer(make([]byte, 0, size))
//	_, err := io.CopyN(buffer, resp.Body, size)
//	if err != nil {
//		return buffer.Bytes(), err
//	}
//	return buffer.Bytes(), err
//}

func stripFirstChar(path string) string {
	if strings.HasPrefix(path, "/") {
		return path[1:]
	}
	return path
}

func getJSRedirectURL(body []byte) (redirectURL string) {
	// 匹配 location.href = 'target.jsp'
	find := regDirectInJS.FindSubmatch(body)
	if len(find) > 1 {
		redirectURL = string(find[1])
		redirectURL = strings.TrimSpace(redirectURL)
		redirectURL = strings.Replace(redirectURL, "&nbsp;", " ", -1)
		return stripFirstChar(redirectURL)
	}

	// 匹配 window.navigate('target.jsp')
	find = regDirectInJS2.FindSubmatch(body)
	if len(find) > 1 {
		redirectURL = string(find[1])
		redirectURL = strings.TrimSpace(redirectURL)
		redirectURL = strings.Replace(redirectURL, "&nbsp;", " ", -1)
		return stripFirstChar(redirectURL)
	}

	// 匹配 window.location.replace('target.jsp')
	find = regDirectInJS3.FindSubmatch(body)
	if len(find) > 1 {
		redirectURL = string(find[1])
		redirectURL = strings.TrimSpace(redirectURL)
		redirectURL = strings.Replace(redirectURL, "&nbsp;", " ", -1)
		return stripFirstChar(redirectURL)
	}

	// 匹配 self.location='target.aspx'
	find = regDirectInJS4.FindSubmatch(body)
	if len(find) > 1 {
		redirectURL = string(find[1])
		redirectURL = strings.TrimSpace(redirectURL)
		redirectURL = strings.Replace(redirectURL, "&nbsp;", " ", -1)
		return stripFirstChar(redirectURL)
	}

	// 匹配 top.location='target.aspx'
	find = regDirectInJS5.FindSubmatch(body)
	if len(find) > 1 {
		redirectURL = string(find[1])
		redirectURL = strings.TrimSpace(redirectURL)
		redirectURL = strings.Replace(redirectURL, "&nbsp;", " ", -1)
		return stripFirstChar(redirectURL)
	}

	// 没有找到任何Jump To
	redirectURL = ""
	return
}

func IdentifyProtocol(host string, Timeout int64) (protocol string) {
	protocol = "http"
	//如果端口是80或443,跳过Protocol判断
	if strings.HasSuffix(host, ":80") || !strings.Contains(host, ":") {
		return
	} else if strings.HasSuffix(host, ":443") {
		protocol = "https"
		return
	}

	socksconn, err := common.GetConn("tcp", host, time.Duration(Timeout)*time.Second)
	if err != nil {
		return
	}
	conn := tls.Client(socksconn, &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true})
	defer func() {
		if conn != nil {
			defer func() {
				if err := recover(); err != nil {
					common.LogError(err)
				}
			}()
			conn.Close()
		}
	}()
	conn.SetDeadline(time.Now().Add(time.Duration(Timeout) * time.Second))
	err = conn.Handshake()
	if err == nil || strings.Contains(err.Error(), "handshake failure") {
		protocol = "https"
	}
	return protocol
}
