package Plugins

import (
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"strings"
	"time"

	"github.com/xxx/wscan/common"
	//"github.com/jlaffaye/ftp"
	"github.com/xxx/wscan/mylib/ftp"
)

func checkAnouymousLogin(info *common.HostInfo) (tmperr error) {
	//status, err := FtpConn(info, "anonymous", "<anypassword>")
	status, err := FtpConn(info, "anonymous", "anonymous")
	if status && err == nil {
		//res := fmt.Sprintf("[+] ftp %v:%v %v", info.Host, info.PortsInput, "anonymous any2")
		//common.LogSuccess(res)
	} else {
		tmperr = err
	}
	return
}

func FtpScan(info *common.HostInfo) (tmperr error) {
	if common.DoBrute == false {
		checkAnouymousLogin(info)
		return
	}
	common.BruteTaskRateCtrlCh <- struct{}{}
	defer func() {
		<-common.BruteTaskRateCtrlCh
	}()
	if err := checkAnouymousLogin(info); err == nil {
		return err
	} else {
		//flag, err := FtpConn(info, "anonymous", "any")
		//if flag && err == nil {
		//	return err
		//} else {
		//	//errlog := fmt.Sprintf("[-] ftp %v:%v %v %v", info.Host, info.PortsInput, "anonymous", "any")
		//	//common.LogError(errlog)
		//	tmperr = err
		//	if common.CheckErrs(err) {
		//		return err
		//	}
		//}

		starttime := time.Now().Unix()
		for _, user := range common.Userdict["ftp"] {
			for _, pass := range common.Passwords {
				pass = strings.Replace(pass, "{user}", user, -1)
				flag, err := FtpConn(info, user, pass)
				if flag && err == nil {
					return err
				} else {
					errlog := fmt.Sprintf("[-] ftp %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
					common.LogError(errlog)
					tmperr = err
					if common.CheckErrs(err) {
						return err
					}
					if time.Now().Unix()-starttime > (int64(len(common.Userdict["ftp"])*len(common.Passwords)) * common.TcpTimeout) {
						return err
					}
				}
			}
		}
	}
	return tmperr
}

func FtpConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	conn, err := ftp.Dial(fmt.Sprintf("%v:%v", Host, Port), ftp.DialWithTimeout(time.Duration(common.TcpTimeout)*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(common.TcpTimeout+3)*time.Second)
	defer cancel()
	res := make(chan error)
	if err == nil {
		go func(conn *ftp.ServerConn) {
			err := conn.Login(user, pass)
			res <- err
		}(conn)
		select {
		case err = <-res:
			break
		case <-ctx.Done(): // 超时或被取消
			//fmt.Println("操作取消:", ctx.Err()) // 输出 context.DeadlineExceeded
			err = errors.New("ftp login timeout")
		}

		//err = conn.Login(Username, Password)
		if err == nil {
			flag = true
			result := fmt.Sprintf("[+] ftp:%v:%v:%v %v", Host, Port, Username, Password)
			dirs, err2 := conn.List(".")
			//defer conn.Logout()
			if err2 == nil {
				if len(dirs) > 0 {
					for i := 0; i < len(dirs); i++ {
						if len(dirs[i].Name) > 50 {
							result += "\n   [->]" + dirs[i].Name[:50]
						} else {
							result += "\n   [->]" + dirs[i].Name
						}
						if i == 5 {
							break
						}
					}
				}
			} else {
				fmt.Println("[debug] ftp list dir err:", err2)
			}
			common.LogSuccess(result)
			err = nil
		}
	}
	return flag, err
}
