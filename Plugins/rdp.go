package Plugins

import (
	"fmt"
	"github.com/xxx/wscan/common"
	"github.com/xxx/wscan/mylib/grdp/glog"
	"github.com/xxx/wscan/mylib/grdp/login"
	"github.com/xxx/wscan/mylib/grdp/protocol/x224"
	"strconv"
	"strings"
	"sync"
)

type Brutelist struct {
	user string
	pass string
}

func RdpScan(info *common.HostInfo) (tmperr error) {
	//通过NLA获取系统信息
	host := info.Host + ":" + info.Ports
	g := login.NewClient(host, login.LogLever)
	osInfo := g.ProbeOSInfo(host, common.Domain, "", "", common.TcpTimeout, x224.PROTOCOL_HYBRID)
	if osInfo != nil {
		//for k, v := range osInfo {
		//	fmt.Printf("get %s : %s\n", k, v)
		//}
		var netBiosDomainName, netBiosComputerName, FQDN, DNSDomainName, ProductVersion, OsVerion string
		if value, exists := osInfo["NetBIOSDomainName"]; exists {
			if field_value, ok := value.(string); ok {
				netBiosDomainName = field_value
			}
		}
		if value, exists := osInfo["NetBIOSComputerName"]; exists {
			if field_value, ok := value.(string); ok {
				netBiosComputerName = field_value
			}
		}
		if value, exists := osInfo["FQDN"]; exists {
			if field_value, ok := value.(string); ok {
				FQDN = field_value
			}
		}
		if value, exists := osInfo["DNSDomainName"]; exists {
			if field_value, ok := value.(string); ok {
				DNSDomainName = field_value
			}
		}
		if value, exists := osInfo["ProductVersion"]; exists {
			if field_value, ok := value.(string); ok {
				ProductVersion = field_value
			}
		}
		if value, exists := osInfo["OsVerion"]; exists {
			if field_value, ok := value.(string); ok {
				OsVerion = field_value
			}
		}
		if OsVerion == "" && netBiosComputerName == "" && FQDN == "" && netBiosDomainName == "" && DNSDomainName == "" {
			return
		}
		osInfoStr := fmt.Sprintf("[+] get os info by rdpscan: %s, Build:Windows %s, OS:(%s), Hostname:%s, DNSDomainName:%s, FQDN:%s, NetBIOSDomainName:%s, DnsdDomainName:%s", host, ProductVersion, OsVerion, netBiosComputerName, netBiosComputerName, FQDN, netBiosDomainName, DNSDomainName)
		common.LogSuccess(osInfoStr)
	}

	if common.IsScreenShot {
		//rdp截屏
		login.Socks5Proxy = common.Socks5Proxy // socks5://127.0.0.1:10808
		login.LogLever = glog.NONE             // TRACE DEBUG INFO WARN ERROR NONE
		status, rdpErr := login.RdpConn(host, common.Domain, "", "", common.TcpTimeout, x224.PROTOCOL_SSL)
		if status == true {
			//fmt.Printf("[+] RDP %v, domain:%v, user:%v pass:%v\n", host, common.Domain, "", "")
			fmt.Printf("[+] RDP:%v:%v %v\n", host, "<any>", "<any>")
			return
		} else {
			errlog := fmt.Sprintf("[-] rdp %v, user:%v pass:%v  err:%v", host, "", "", rdpErr)
			errlog += ""
			//fmt.Println(errlog)
			//if rdpErr != nil && strings.Contains(rdpErr.Error(), "dial err") {
			//	fmt.Println(info.Host, "端口未开放")
			//}
		}
	}

	if common.DoBrute == false {
		return
	}
	common.BruteTaskRateCtrlCh <- struct{}{}
	defer func() {
		<-common.BruteTaskRateCtrlCh
	}()
	var wg sync.WaitGroup
	var signal bool
	var num = 0
	var all = len(common.Userdict["rdp"]) * len(common.Passwords)
	var mutex sync.Mutex
	brlist := make(chan Brutelist)
	port, _ := strconv.Atoi(info.Ports)

	for i := 0; i < common.BruteThread; i++ {
		wg.Add(1)
		go worker(info.Host, common.Domain, port, &wg, brlist, &signal, &num, all, &mutex, common.TcpTimeout)
	}

	for _, user := range common.Userdict["rdp"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			brlist <- Brutelist{user, pass}
		}
	}
	close(brlist)
	go func() {
		wg.Wait()
		signal = true
	}()
	for !signal {
	}

	return tmperr
}

func worker(host, domain string, port int, wg *sync.WaitGroup, brlist chan Brutelist, signal *bool, num *int, all int, mutex *sync.Mutex, timeout int64) {
	defer wg.Done()
	for one := range brlist {
		if *signal == true {
			return
		}
		go incrNum(num, mutex)
		user, pass := one.user, one.pass
		flag, err := login.RdpCrack(host+":"+strconv.Itoa(port), domain, user, pass, common.TcpTimeout, x224.PROTOCOL_SSL)
		if flag == true {
			targetDomain := common.Domain
			if targetDomain == "" {
				targetDomain = "WORKGROUP"
			}
			//result := fmt.Sprintf("[+] RDP %v, domain:%v, user:%v pass:%v\n", host+":"+strconv.Itoa(port), targetDomain, user, pass)
			result := fmt.Sprintf("[+] RDP:%v:%v %v\n", host+":"+strconv.Itoa(port), user, pass)
			common.LogSuccess(result)
			*signal = true
			return
		} else if err != nil {
			errlog := fmt.Sprintf("[-] rdp (%v/%v) %v, user:%v pass:%v  err:%v", *num, all, host+":"+strconv.Itoa(port), user, pass, err.Error())
			errlog += ""
			//fmt.Println(errlog)
			if err != nil && strings.Contains(err.Error(), "dial err") {
				//fmt.Println(host+":"+strconv.Itoa(port), "端口未开放")
			}
		}

		//flag, err := RdpConn(host, domain, user, pass, port, timeout)
		//if flag == true && err == nil {
		//	var result string
		//	if domain != "" {
		//		result = fmt.Sprintf("[+] RDP %v:%v:%v\\%v %v", host, port, domain, user, pass)
		//	} else {
		//		result = fmt.Sprintf("[+] RDP %v:%v:%v %v", host, port, user, pass)
		//	}
		//	common.LogSuccess(result)
		//	*signal = true
		//	return
		//} else {
		//	errlog := fmt.Sprintf("[-] (%v/%v) rdp %v:%v %v %v %v", *num, all, host, port, user, pass, err)
		//	common.LogError(errlog)
		//}
	}
}

func incrNum(num *int, mutex *sync.Mutex) {
	mutex.Lock()
	*num = *num + 1
	mutex.Unlock()
}
