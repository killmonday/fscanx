package Plugins

import (
	"errors"
	"fmt"
	"github.com/killmonday/fscanx/mylib/stdio/chinese"
	"golang.org/x/net/context"
	"strings"
	"time"

	"github.com/killmonday/fscanx/common"
	//"github.com/jlaffaye/ftp"
	"github.com/killmonday/fscanx/mylib/ftp"
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

func walkFtpDir(conn *ftp.ServerConn, path string, index int8) string {
	if index == 4 {
		// 遍历所有子文件夹，但整体都都不超过3级，从根目录.算起，根目录为第1级
		return ""
	}
	entries, err := conn.List(path)
	fileListStr := "\n [->]Current dir: " + path
	if err != nil {
		return ""
	}
	floders := []string{}
	for _, entry := range entries {
		name := chinese.ToUTF8(entry.Name)
		// 如果是目录，递归遍历
		if entry.Type == ftp.EntryTypeFolder && name != "." && name != ".." {
			fileListStr += "\n   [->] [dir] " + name
			floders = append(floders, path+"/"+name)
		} else {
			fileListStr += "\n   [->] " + name
		}
	}
	for _, floder := range floders {
		fileListStr += walkFtpDir(conn, floder, index+1)
	}

	return fileListStr
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
			result += walkFtpDir(conn, ".", 1)
			common.LogSuccess(result)
			err = nil
		}
	}
	return flag, err
}
