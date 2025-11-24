package common

import (
	"flag"
	"fmt"
	"github.com/alitto/pond"
	"github.com/bits-and-blooms/bloom/v3"
	"os"
	"strings"
	"time"

	"github.com/killmonday/fscanx/mylib/grdp/login"
	_ "github.com/projectdiscovery/fdmax/autofdmax" //自动增加当前go程序的文件描述符的最大数量
)

func Banner() {
	banner := `
$$$$$$$$\                                         $$$$$$\ $$\     
$$  _____|                                        \_$$  _|$$ |    
$$ |      $$$$$$$\  $$\  $$$$$$\  $$\   $$\         $$ |$$$$$$\   
$$$$$\    $$  __$$\ \__|$$  __$$\ $$ |  $$ |        $$ |\_$$  _|  
$$  __|   $$ |  $$ |$$\ $$ /  $$ |$$ |  $$ |        $$ |  $$ |    
$$ |      $$ |  $$ |$$ |$$ |  $$ |$$ |  $$ |        $$ |  $$ |$$\ 
$$$$$$$$\ $$ |  $$ |$$ |\$$$$$$  |\$$$$$$$ |      $$$$$$\ \$$$$  |
\________|\__|  \__|$$ | \______/  \____$$ |      \______| \____/ 
              $$\   $$ |          $$\   $$ |                      
              \$$$$$$  |          \$$$$$$  |                      
               \______/            \______/                                             
` + version + `
`
	print(banner)
}

func Flag(Info *HostInfo) {
	Banner()
	flag.StringVar(&Info.Host, "h", "", "IP address of the host you want to scan,for example: 192.168.11.11 | 192.168.11.11-255 | 192.168.11.11,192.168.11.12")
	flag.StringVar(&NoHosts, "hn", "", "the hosts no scan,as: -hn 192.168.1.1/24")
	flag.StringVar(&PortsInput, "p", DefaultPorts, "Select a port,for example: 22 | 1-65535 | 22,80,3306")
	flag.StringVar(&PortAdd, "pa", "", "add port base DefaultPorts,-pa 3389")
	flag.StringVar(&UserAdd, "usera", "", "add a user base DefaultUsers,-usera user")
	flag.StringVar(&PassAdd, "pwda", "", "add a password base DefaultPasses,-pwda password")
	flag.StringVar(&NotScanPorts, "pn", "", "the ports no scan,as: -pn 445")
	flag.StringVar(&Command, "c", "", "exec command (ssh|wmiexec)")
	flag.StringVar(&SshKey, "sshkey", "", "sshkey file (id_rsa)")
	flag.StringVar(&Domain, "domain", "", "smb domain")
	flag.StringVar(&Username, "user", "", "username")
	flag.StringVar(&Password, "pwd", "", "password")
	flag.Int64Var(&TcpTimeout, "time", 6, "Set port scan tcp timeout")
	flag.StringVar(&Scantype, "m", "all", "Select task type(it will impact probe ports and task),example: -m icmp/web/webpoc...")
	flag.StringVar(&Path, "path", "", "fcgi、smb romote file path")
	flag.IntVar(&PortScanThreadNum, "t", 512, "Port scan Thread nums")
	flag.IntVar(&LiveTop, "top", 10, "show live len top")
	flag.StringVar(&HostFile, "hf", "", "host file, -hf ip.txt")
	flag.StringVar(&Userfile, "userf", "", "username file")
	flag.StringVar(&Passfile, "pwdf", "", "password file")
	flag.StringVar(&PortFile, "portf", "", "Port File")
	flag.StringVar(&PocPath, "pocpath", "", "poc file path")
	flag.StringVar(&RedisFile, "rf", "", "redis file to write sshkey file (as: -rf id_rsa.pub)")
	flag.StringVar(&RedisShell, "rs", "", "redis shell to write cron file (as: -rs 192.168.1.1:6666)")
	flag.BoolVar(&IsCheckPoc, "poc", false, "scan vuln?")
	flag.BoolVar(&DoBrute, "br", false, "do brute?")
	flag.IntVar(&BruteThread, "bt", 24, "Brute threads")
	flag.BoolVar(&NoPing, "np", false, "not to ping")
	flag.BoolVar(&UsePingExe, "ping", false, "using ping cmd replace icmp conn")
	flag.StringVar(&Outputfile, "o", "result.txt", "Outputfile")
	flag.BoolVar(&TmpSave, "no", false, "not to save output log")
	flag.Int64Var(&WaitTime, "debug", 60, "every time to LogErr")
	flag.BoolVar(&Silent, "silent", false, "silent scan")
	flag.BoolVar(&Nocolor, "nocolor", false, "no color")
	flag.BoolVar(&PocFull, "full", false, "poc full scan,as: shiro 100 key")
	flag.StringVar(&URL, "u", "", "url")
	flag.StringVar(&UrlFile, "uf", "", "urlfile")
	flag.StringVar(&Pocinfo.PocName, "pocname", "", "use the pocs these contain pocname, -pocname weblogic")
	flag.StringVar(&Proxy, "proxy", "", "set poc proxy, -proxy http://127.0.0.1:8080")
	flag.StringVar(&Socks5Proxy, "socks5", "", "set socks5 proxy, will be used in tcp connection, timeout setting will not work")
	flag.StringVar(&Cookie, "cookie", "", "set poc cookie,-cookie rememberMe=login")
	flag.Int64Var(&WebTimeout, "wt", 9, "Set web timeout")
	flag.BoolVar(&DnsLog, "dns", false, "using dnslog poc")
	flag.IntVar(&PocNum, "num", 30, "poc rate")
	flag.StringVar(&SC, "sc", "", "ms17 shellcode,as -sc add")
	flag.BoolVar(&IsWmi, "wmi", false, "start wmi")
	flag.StringVar(&Hash, "hash", "", "hash")
	flag.BoolVar(&Noredistest, "noredis", false, "no redis sec test")
	flag.BoolVar(&JsonOutput, "json", false, "json output")
	flag.BoolVar(&UseNmap, "nmap", false, "using gonmap to check protocol")           //own add
	flag.StringVar(&Iface, "iface", "", "local ip of iface want to use")              //own add
	flag.Float64Var(&PingRate, "prate", 0.1, "rate for icmp scan")                    //own add
	flag.IntVar(&PingTimeout, "pt", 5, "ping timeout")                                //own add
	flag.IntVar(&WebScanThreadNum, "tn", 60, "Web(http/https only) scan Thread nums") //own add
	flag.BoolVar(&IsScreenShot, "screen", false, "make and save rdp screenshot")      //own add
	flag.BoolVar(&ScanWithStdInput, "std", false, "read ip:port from stdin, one per line")
	flag.BoolVar(&AutoScanBigCidr, "auto", false, "auto scan big cidr")
	flag.StringVar(&AutoScanProtocols, "am", "tcp,icmp", "auto scan with which protocol, default: tcp,icmp")
	flag.StringVar(&AutoScanPorts, "ap", "80", "which port need to scan with autoscan task, default: 80")
	flag.StringVar(&AUtoScanIPLocation, "ai", "1,2,253,254", "which location of a cnet need to scan, default: 1,2,253,254")
	flag.IntVar(&AutoScanTcpTimeout, "atime", 3, "port scan timeout with auto scan task")
	flag.BoolVar(&IsParseDomain, "pd", false, "is parse domain to ip and add to port scan")

	flag.Parse()

	if ScanWithStdInput {
		// 在-std模式下，http扫描的速率设置和端口扫描速率一样，使用-t参数控制，这样简单点
		WebScanRateCtrlCh = make(chan struct{}, PortScanThreadNum)
	} else {
		WebScanRateCtrlCh = make(chan struct{}, WebScanThreadNum)
	}
	PluginTaskRateCtrlCh = make(chan struct{}, WebScanThreadNum+BruteThread) //该通道用来控制插件类型的所有任务的整体并发数。其中，口令爆破任务、web探测任务还有自己额外的并发控制
	BruteTaskRateCtrlCh = make(chan struct{}, BruteThread)
	PoolScan = pond.New(PortScanThreadNum*5+WebScanThreadNum+BruteThread, PortScanThreadNum*25) // gopool.WithMinWorkers(PortScanThreadNum)
	NmapTotalTimeout = time.Second * time.Duration(TcpTimeout*4)                                //4个探针时间
	NmapSingleProbeTimeout = time.Second * time.Duration(TcpTimeout)

	if IsScreenShot {
		nowTimestamp := time.Now().Format("2006_01_02_15_04_05")
		login.OutputDir = "img/" + nowTimestamp
		if _, err := os.Stat(login.OutputDir); os.IsNotExist(err) {
			mkdirErr := os.MkdirAll(login.OutputDir, 0755)
			if mkdirErr != nil {
				fmt.Println("Can not create rdp screenshot output dir:", mkdirErr)
			}
		}
	}

	initDialer(time.Duration(TcpTimeout) * time.Second)
	if (AutoScanBigCidr && strings.Contains(AutoScanProtocols, "icmp")) || (NoPing != true && ScanWithStdInput == false) {
		BloomFilter = bloom.NewWithEstimates(16780000, 0.01)
	}
}
