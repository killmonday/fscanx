package Plugins

import (
	"errors"
	"fmt"
	iofs "io/fs"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
	"github.com/killmonday/fscanx/common"
)

func SmbScan(info *common.HostInfo) (tmperr error) {
	if common.DoBrute == false {
		conn, err := common.GetConn("tcp", info.Host+":"+info.Ports, time.Duration(common.TcpTimeout*2)*time.Second)
		if err != nil {
			return
		}
		defer conn.Close()

		d := &smb2.Dialer{
			Initiator: &smb2.NTLMInitiator{
				User:     "guest",
				Password: "",
			},
		}
		s, err := d.Dial(conn) // 登录认证
		if err != nil {
			//fmt.Println("smb login fail:", err)
			return err
		}
		res := fmt.Sprintf("[+] smb %s allow anonymous login", info.Host+":"+info.Ports)
		//common.LogSuccess(res)
		defer s.Logoff()

		// 尝试列出所有共享目录
		shares, err := s.ListSharenames()
		if err != nil {
			fmt.Printf("can not list shares: %v\n", err)
			return
		} else {
			//fmt.Println(shares)
		}
	listSharesDir:
		for _, shareName := range shares {
			fs, err := s.Mount(shareName)
			if err != nil {
				//fmt.Println("Mount", shareName, "err:", err)
				continue
			}
			defer fs.Umount()
			//fmt.Println("share name len:", len(shareName), shareName)
			for _, doNotDisplay := range []string{"ADMIN$", "C$", "IPC$"} {
				if shareName == doNotDisplay {
					continue listSharesDir
				} else {
					//fmt.Println(shareName, doNotDisplay)
				}
			}

			//matches, err := iofs.Glob(fs.DirFS("."), "*")
			//if err != nil {
			//	//panic(err)
			//	continue
			//}
			//for _, match := range matches {
			//	//fmt.Println(match)
			//	match += ""
			//}

			err = iofs.WalkDir(fs.DirFS("."), ".", func(path string, d iofs.DirEntry, err error) error {
				if path != "." {
					res += fmt.Sprintf("\n   [->] [%s] %s", shareName, path)
					//common.LogSuccess(fmt.Sprintf("[+] smb %s explorer, sharename[%s]: %s\n", info.Host+":"+info.PortsInput, shareName, path))
				}
				return nil
			})
			if err != nil {
				fmt.Println(err)
			}
		}
		common.LogSuccess(res)
		return nil
	}

	//
	starttime := time.Now().Unix()
	for _, user := range common.Userdict["smb"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := doWithTimeOut(info, user, pass)
			if flag == true && err == nil {
				var result string
				if common.Domain != "" {
					result = fmt.Sprintf("[+] SMB:%v:%v:%v\\%v %v", info.Host, info.Ports, common.Domain, user, pass)
				} else {
					result = fmt.Sprintf("[+] SMB:%v:%v:%v %v", info.Host, info.Ports, user, pass)
				}
				common.LogSuccess(result)
				return err
			} else {
				errlog := fmt.Sprintf("[-] smb %v:%v %v %v %v", info.Host, 445, user, pass, err)
				errlog = strings.Replace(errlog, "\n", "", -1)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(common.Userdict["smb"])*len(common.Passwords)) * common.TcpTimeout) {
					return err
				}
			}
		}
	}
	return tmperr
}

func SmblConn(info *common.HostInfo, user string, pass string, signal chan struct{}) (flag bool, err error) {
	flag = false
	//options := smb.Options{
	//	Host:        Host,
	//	Port:        445,
	//	User:        Username,
	//	Password:    Password,
	//	Domain:      common.Domain,
	//	Workstation: "",
	//}
	//
	//session, err := smb.NewSession(options, false)
	//if err == nil {
	//	session.Close()
	//	if session.IsAuthenticated {
	//		flag = true
	//	}
	//}
	//signal <- struct{}{}
	//return flag, err
	defer func() { signal <- struct{}{} }()
	conn, err := common.GetConn("tcp", info.Host+":"+info.Ports, time.Duration(common.TcpTimeout*2)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     user,
			Password: pass,
		},
	}
	_, err = d.Dial(conn) // 登录认证
	if err == nil {
		flag = true
	}
	return flag, err
}

func doWithTimeOut(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	signal := make(chan struct{})
	go func() {
		flag, err = SmblConn(info, user, pass, signal)
		signal <- struct{}{}
	}()
	timeout := common.TcpTimeout
	if timeout < 12 {
		timeout = 12
	}
	select {
	case <-signal:
		return flag, err
	case <-time.After(time.Duration(timeout) * time.Second):
		return false, errors.New("smb conn time out")
	}
}
