package common

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/juju/ratelimit"
)

func Parse(Info *HostInfo) {
	ParseUser()
	ParsePass(Info)
	ParseInput(Info)
	ParseScantype(Info)
	Info.Ports = PortsInput
}

func ParseUser() {
	if Username == "" && Userfile == "" {
		return
	}
	var Usernames []string
	if Username != "" {
		Usernames = strings.Split(Username, ",")
	}

	if Userfile != "" {
		users, err := Readfile(Userfile)
		if err == nil {
			for _, user := range users {
				if user != "" {
					Usernames = append(Usernames, user)
				}
			}
		}
	}

	Usernames = RemoveDuplicate(Usernames)
	for name := range Userdict {
		Userdict[name] = Usernames
	}
}

func ParsePass(Info *HostInfo) {
	var PwdList []string
	if Password != "" {
		passs := strings.Split(Password, ",")
		for _, pass := range passs {
			if pass != "" {
				PwdList = append(PwdList, pass)
			}
		}
		Passwords = PwdList
	}
	if Passfile != "" {
		passs, err := Readfile(Passfile)
		if err == nil {
			for _, pass := range passs {
				if pass != "" {
					PwdList = append(PwdList, pass)
				}
			}
			Passwords = PwdList
		}
	}
	if URL != "" {
		urls := strings.Split(URL, ",")
		TmpUrls := make(map[string]struct{})
		for _, url := range urls {
			if _, ok := TmpUrls[url]; !ok {
				TmpUrls[url] = struct{}{}
				if url != "" {
					Urls = append(Urls, url)
				}
			}
		}
	}
	if UrlFile != "" {
		urls, err := Readfile(UrlFile)
		if err == nil {
			TmpUrls := make(map[string]struct{})
			for _, url := range urls {
				if _, ok := TmpUrls[url]; !ok {
					TmpUrls[url] = struct{}{}
					if url != "" {
						Urls = append(Urls, url)
					}
				}
			}
		}
	}
	if PortFile != "" {
		ports, err := Readfile(PortFile)
		if err == nil {
			newport := ""
			for _, port := range ports {
				if port != "" {
					newport += port + ","
				}
			}
			PortsInput = newport
		}
	}

}

func Readfile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Open %s error, %v\n", filename, err)
		os.Exit(0)
	}
	defer file.Close()
	var content []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			content = append(content, scanner.Text())
		}
	}
	return content, nil
}

func ParseInput(Info *HostInfo) {
	if Info.Host == "" && HostFile == "" && URL == "" && UrlFile == "" {
		if ScanWithStdInput == false {
			fmt.Println("Host is none")
			flag.Usage()
			os.Exit(0)
		}
	}

	if BruteThread <= 0 {
		BruteThread = 5
	}

	if TmpSave == true {
		IsSave = false
	}

	if PortAdd != "" {
		if strings.HasSuffix(PortsInput, ",") {
			PortsInput += PortAdd
		} else {
			PortsInput += "," + PortAdd
		}
	}

	if UserAdd != "" {
		user := strings.Split(UserAdd, ",")
		for a := range Userdict {
			Userdict[a] = append(Userdict[a], user...)
			Userdict[a] = RemoveDuplicate(Userdict[a])
		}
	}

	if PassAdd != "" {
		pass := strings.Split(PassAdd, ",")
		Passwords = append(Passwords, pass...)
		Passwords = RemoveDuplicate(Passwords)
	}
	if Socks5Proxy != "" && !strings.HasPrefix(Socks5Proxy, "socks5://") {
		if !strings.Contains(Socks5Proxy, ":") {
			Socks5Proxy = "socks5://127.0.0.1" + Socks5Proxy
		} else {
			Socks5Proxy = "socks5://" + Socks5Proxy
		}
	}
	if Socks5Proxy != "" {
		fmt.Println("Socks5Proxy:", Socks5Proxy)
		_, err := url.Parse(Socks5Proxy)
		if err != nil {
			fmt.Println("Socks5Proxy parse error:", err)
			os.Exit(0)
		}
		NoPing = true
	}
	if Proxy != "" {
		if Proxy == "1" {
			Proxy = "http://127.0.0.1:8080"
		} else if Proxy == "2" {
			Proxy = "socks5://127.0.0.1:1080"
		} else if !strings.Contains(Proxy, "://") {
			Proxy = "http://127.0.0.1:" + Proxy
		}
		fmt.Println("Proxy:", Proxy)
		if !strings.HasPrefix(Proxy, "socks") && !strings.HasPrefix(Proxy, "http") {
			fmt.Println("no support this proxy")
			os.Exit(0)
		}
		_, err := url.Parse(Proxy)
		if err != nil {
			fmt.Println("Proxy parse error:", err)
			os.Exit(0)
		}
	}

	if Hash != "" && len(Hash) != 32 {
		fmt.Println("[-] Hash is error,len(hash) must be 32")
		os.Exit(0)
	} else {
		Hashs = append(Hashs, Hash)
	}
	Hashs = RemoveDuplicate(Hashs)
	for _, hash := range Hashs {
		hashbyte, err := hex.DecodeString(Hash)
		if err != nil {
			fmt.Println("[-] Hash is error,hex decode error ", hash)
			continue
		} else {
			HashBytes = append(HashBytes, hashbyte)
		}
	}
	Hashs = []string{}

	//own add
	MaxRate = MaxRate * PingRate //根据用户设置的PingRate(例如0.1)，计算出本次icmp任务最大发包为多少MB/s
	// 计算发送一个 ICMP 数据包所需的时间
	PacketsPerSecond = MaxRate / float64(PacketSize)
	Bucket_limit = int64(PacketsPerSecond)
	PacketTime = time.Second / time.Duration(PacketsPerSecond)
	// 创建令牌桶，参数分别为：填充令牌的时间间隔，令牌桶的令牌数上限，每次填充的令牌数量
	Limiter = ratelimit.NewBucketWithQuantum(PacketTime, Bucket_limit, int64(1))
}

func ParseScantype(Info *HostInfo) {
	_, ok := PluginPortMap[Scantype]
	if !ok {
		showmode()
	}
	//根据用户设置的扫描类型，改变探测的端口列表
	if Scantype != "all" {
		switch Scantype {
		case "wmiexec":
			PortsInput = "135"
		case "wmiinfo":
			PortsInput = "135"
		case "smbinfo":
			PortsInput = "445"
		case "hostname":
			PortsInput = "135,137,139,445"
		case "smb2":
			PortsInput = "445"
		case "web":
			PortsInput = Webport
		case "webonly":
			PortsInput = Webport
		case "ms17010":
			PortsInput = "445"
		case "cve20200796":
			PortsInput = "445"
		case "portscan":
			PortsInput = DefaultPorts + "," + Webport
		case "main":
			PortsInput = DefaultPorts
		default:
			port, ok := PluginPortMap[Scantype]
			if ok {
				PortsInput = strconv.Itoa(port)
			}
		}
	}

}

func CheckErr(text string, err error, flag bool) {
	if err != nil {
		fmt.Println("Parse", text, "error: ", err.Error())
		if flag {
			if err != ParseIPErr {
				fmt.Println(ParseIPErr)
			}
			os.Exit(0)
		}
	}
}

func showmode() {
	fmt.Println("The specified scan type does not exist")
	fmt.Println("-m")
	for name := range PluginPortMap {
		fmt.Println("   [" + name + "]")
	}
	os.Exit(0)
}
