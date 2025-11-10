package Plugins

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	"github.com/xxx/wscan/common"
	//"golang.org/x/crypto/ssh"
	"github.com/xxx/wscan/mylib/ssh"
)

func SshScan(info *common.HostInfo) (tmperr error) {
	if common.DoBrute == false {
		return
	}
	common.BruteTaskRateCtrlCh <- struct{}{}
	defer func() {
		<-common.BruteTaskRateCtrlCh
	}()
	starttime := time.Now().Unix()
	for _, user := range common.Userdict["ssh"] {
		for _, pass := range common.Passwords {
			pass = strings.Replace(pass, "{user}", user, -1)
			flag, err := SshConn(info, user, pass)
			if flag == true && err == nil {
				return err
			} else {
				errlog := fmt.Sprintf("[-] ssh %v:%v %v %v %v", info.Host, info.Ports, user, pass, err)
				common.LogError(errlog)
				tmperr = err
				if common.CheckErrs(err) {
					return err
				}
				if time.Now().Unix()-starttime > (int64(len(common.Userdict["ssh"])*len(common.Passwords)) * common.TcpTimeout) {
					return err
				}
			}
			if common.SshKey != "" {
				return err
			}
		}
	}
	return tmperr
}

func SshConn(info *common.HostInfo, user string, pass string) (flag bool, err error) {
	flag = false
	Host, Port, Username, Password := info.Host, info.Ports, user, pass
	var Auth []ssh.AuthMethod
	if common.SshKey != "" {
		pemBytes, err := ioutil.ReadFile(common.SshKey)
		if err != nil {
			return false, errors.New("read key failed" + err.Error())
		}
		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return false, errors.New("parse key failed" + err.Error())
		}
		Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	} else {
		Auth = []ssh.AuthMethod{ssh.Password(Password)}
	}

	config := &ssh.ClientConfig{
		User:    Username,
		Auth:    Auth,
		Timeout: time.Duration(common.TcpTimeout) * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	conn, err := common.WrapperTcpWithTimeout("tcp", info.Host+":"+info.Ports, time.Duration(common.TcpTimeout*2)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	c, chans, reqs, err := ssh.NewClientConn(conn, info.Host+":"+info.Ports, config)
	if err != nil {
		return flag, err
	}

	//client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", Host, Port), config)
	client := ssh.NewClient(c, chans, reqs)
	if err == nil {
		defer client.Close()
		session, err := client.NewSession()
		if err == nil {
			defer session.Close()
			flag = true
			var result string
			if common.Command != "" {
				combo, _ := session.CombinedOutput(common.Command)
				result = fmt.Sprintf("[+] SSH:%v:%v:%v %v \n %v", Host, Port, Username, Password, string(combo))
				if common.SshKey != "" {
					result = fmt.Sprintf("[+] SSH %v:%v sshkey correct \n %v", Host, Port, string(combo))
				}
				common.LogSuccess(result)
			} else {
				result = fmt.Sprintf("[+] SSH:%v:%v:%v %v", Host, Port, Username, Password)
				if common.SshKey != "" {
					result = fmt.Sprintf("[+] SSH %v:%v sshkey correct", Host, Port)
				}
				common.LogSuccess(result)
			}
		}
	}
	return flag, err

}
