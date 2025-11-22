package Plugins

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/killmonday/fscanx/common"
	"strings"
	"testing"
	"time"
)

func TmpWindows_version_probe(ip string) error {
	conn_smb2_methodA, err := common.GetConn("tcp", ip+":445", time.Second*12)
	if err != nil {
		//fmt.Printf("failed to connect to %s\n", ip)
		return err
	}
	defer conn_smb2_methodA.Close()
	err = conn_smb2_methodA.SetDeadline(time.Now().Add(time.Second * 12))
	if err != nil {
		//fmt.Printf("failed to connect to %s\n", ip)
		return err
	}

	reponse_byte := make([]byte, 1024)
	_, err = conn_smb2_methodA.Write(smb2_new_q1)
	if err != nil {
		return err
	}

	_, err = conn_smb2_methodA.Read(reponse_byte)
	if err != nil {
		// if conn err, try another probe method
		conn_smb2_methodB, err := common.GetConn("tcp", ip+":445", time.Second*12)
		if err != nil {
			//fmt.Printf("failed to connect to %s\n", ip)
			return err
		}
		defer conn_smb2_methodB.Close()
		err = conn_smb2_methodB.SetDeadline(time.Now().Add(time.Second * 12))
		if err != nil {
			//fmt.Printf("failed to connect to %s\n", ip)
			return err
		}

		var n int
		rep_byte := make([]byte, 1024)
		_, err = conn_smb2_methodB.Write(smb2_negotiateProtocolRequest)
		if err != nil {
			return err
		}
		_, err = conn_smb2_methodB.Read(rep_byte)
		if err != nil {
			//fmt.Println("fail to read x2")
			return err
		}

		_, err = conn_smb2_methodB.Write(smb2_query1)
		if err != nil {
			return err
		}
		_, err = conn_smb2_methodB.Read(rep_byte)
		if err != nil {
			return err
		}

		_, err = conn_smb2_methodB.Write(smb2_query2)
		if err != nil {
			return err
		}

		rep_byte = make([]byte, 2048)
		n, err = conn_smb2_methodB.Read(rep_byte)
		if err != nil || n < 68 {
			return err
		}

		// extract OS info
		sessionSetupResponse := rep_byte[68:n]

		// 寻找连续8个空字节的位置
		last_null_byte_index := 0
		tmp_bytes := make([]byte, len(sessionSetupResponse))
		copy(tmp_bytes, sessionSetupResponse)
		for {
			tmp_lengh := len(tmp_bytes)
			if last_null_byte_index > tmp_lengh {
				return err
			}
			tmp_bytes = tmp_bytes[last_null_byte_index:]
			pos := bytes.Index(tmp_bytes, []byte{0x00})
			//fmt.Println("find null byte index: ", pos, "last index:", last_null_byte_index)
			if pos >= 0 {
				last_null_byte_index = pos + 1
				// 检查其后是否有连续的8个空字节
				//fmt.Println("last 8 bit: ", tmp_bytes[pos:pos+8])
				if bytes.HasPrefix(tmp_bytes[pos:], make([]byte, 8)) { //make([]byte, 8) 创建了一个包含8个零值字节的切片，用作 bytes.HasPrefix 的参数。如果从空字节开始的切片以这个零字节序列为前缀，那么意味着我们找到了连续的8个空字节
					//fmt.Printf("找到连续的8个空字节，起始位置为: %d\n", pos)
					tmp_bytes = tmp_bytes[pos:]
					break
				}
			} else {
				//fmt.Println("未找到空字节")
				return err
			}
		}

		if len(tmp_bytes) > 24 {
			os_info := tmp_bytes[8+8 : 8+8+8]
			os_major_version := os_info[0]
			os_minor_version := os_info[1]
			os_build_number := binary.LittleEndian.Uint16(os_info[2:4]) // 使用binary.LittleEndian.Uint16解析小端序的16位整数

			result := ""
			if os_build_number >= 22000 {
				result = fmt.Sprintf("[*] OsInfo %s\t(Windows 11, version:%d.%d.%d) ", ip, os_major_version, os_minor_version, os_build_number)
			} else {
				result = fmt.Sprintf("[*] OsInfo %s\t(Windows %d.%d.%d) ", ip, os_major_version, os_minor_version, os_build_number)
			}
			common.LogSuccess(result)

			// own add ######################################
			fmt.Println("fuccccc222")

			ntlmFlag := []byte("NTLMSSP")
			start := bytes.Index(rep_byte, ntlmFlag) // 查找字节串的位置

			netbiosDomainName, dnsDomainName, FQDN := "None", "None", "None"
			if start != -1 {
				//fmt.Printf("Found 'NTLMSSP' at position: %d\n", start)
				for payload, itemName := range NetBIOS_ITEM_TYPE {
					new_buffer := rep_byte[start+7+6:]
					netbios_postion := bytes.Index(new_buffer, []byte(payload))
					//fmt.Println("netbios_postion=", netbios_postion)
					itemLen := int(new_buffer[netbios_postion+2])
					//fmt.Println("itemLen=", itemLen)
					item := new_buffer[netbios_postion+2+1+1 : netbios_postion+2+1+1+itemLen]
					fmt.Println("item=", item)

					utf8Str := LittleEndUtf16ToUtf8Str(item)

					fmt.Println("转换后的UTF-8字符串:", utf8Str)

					//####
					cleanItem := strings.ReplaceAll(string(item), "\x00", "")
					fmt.Printf("[*] get %s = %s\n", itemName, cleanItem)
					if itemName == "NetBiosDomainName" {
						netbiosDomainName = cleanItem
					}
					if itemName == "DomainName" {
						dnsDomainName = cleanItem
					}
					if itemName == "ComputerName" {
						FQDN = cleanItem
					}
				}
			}

			result2 := fmt.Sprintf("[*] OsInfo %s\t(W) [%s] [%s] [%s]", ip, netbiosDomainName, dnsDomainName, FQDN)
			common.LogSuccess(result2)

		}
	}

	reponse_byte = make([]byte, 1024)
	_, err = conn_smb2_methodA.Write(smb2_new_q2)
	if err != nil {
		return err
	}
	_, err = conn_smb2_methodA.Read(reponse_byte)
	if err != nil {
		return err
	}

	rest_num := int(reponse_byte[43])
	os_version := reponse_byte[rest_num+47 : 1024-rest_num-47]

	os_version_str := string(os_version[:])
	slice := strings.Split(os_version_str, "\x00\x00\x00W")
	if len(slice) >= 2 {
		// clean_str := strings.TrimFunc(slice[1], func(r rune) bool {
		// 	return r == '\x00'
		// })
		clean_str := strings.ReplaceAll(slice[1], "\x00", "")
		result := fmt.Sprintf("[*] OsInfo %s\t(W%s) ", ip, clean_str)
		common.LogSuccess(result)
		fmt.Println("fuccccc")

		ntlmFlag := []byte("NTLMSSP")
		start := bytes.Index(reponse_byte, ntlmFlag) // 查找字节串的位置

		if start != -1 {
			fmt.Printf("Found 'NTLMSSP' at position: %d\n", start)
		} else {
			fmt.Printf("'NTLMSSP' not found")
		}

		netbiosDomainName, dnsDomainName, FQDN := "None", "None", "None"
		for payload, itemName := range NetBIOS_ITEM_TYPE {
			new_buffer := reponse_byte[start+7+6:]
			netbios_postion := bytes.Index(new_buffer, []byte(payload))
			//fmt.Println("netbios_postion=", netbios_postion)
			itemLen := int(new_buffer[netbios_postion+2])
			//fmt.Println("itemLen=", itemLen)
			item := new_buffer[netbios_postion+2+1+1 : netbios_postion+2+1+1+itemLen]
			//fmt.Println("item=", item)
			cleanItem := strings.ReplaceAll(string(item), "\x00", "")
			fmt.Printf("[*] get %s = %s\n", itemName, cleanItem)
			if itemName == "NetBiosDomainName" {
				netbiosDomainName = cleanItem
			}
			if itemName == "DomainName" {
				dnsDomainName = cleanItem
			}
			if itemName == "ComputerName" {
				FQDN = cleanItem
			}
		}
		result2 := fmt.Sprintf("[*] OsInfo %s\t(W%s) [%s] [%s] [%s]", ip, clean_str, netbiosDomainName, dnsDomainName, FQDN)
		common.LogSuccess(result2)

	}

	return err
}

func TestMS17010Scan(t *testing.T) {
	is_os_probe__success := false
	//ip := "192.168.111.123"
	ip := "192.168.111.27"
	// connecting to a host in LAN if reachable should be very quick
	conn, err := common.GetConn("tcp", ip+":445", time.Second*12)
	if err := conn.SetDeadline(time.Now().Add(time.Second * 12)); err != nil {
		fmt.Println("Error setting conn write deadline:", err)
		return
	}
	if err != nil {
		fmt.Printf("failed to connect to %s\n", ip)
		return
	}
	defer conn.Close()
	if err != nil {
		//fmt.Printf("failed to connect to %s\n", ip)
		fmt.Printf("failed : %s\n", err)
		return
	}
	_, err = conn.Write(negotiateProtocolRequest)
	if err != nil {
		err = TmpWindows_version_probe(ip)
		fmt.Println(err)
		return
	}
	reply := make([]byte, 1024)
	// let alone half packet
	if n, err := conn.Read(reply); err != nil || n < 36 {
		fmt.Printf("failed to read 1 to %s, err: %v\n", ip, err)
		err = TmpWindows_version_probe(ip)
		fmt.Println(err)
		return
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		// status != 0
		err = TmpWindows_version_probe(ip)
		fmt.Println(err)
		return
	}

	_, err = conn.Write(sessionSetupRequest)
	if err != nil {
		err = TmpWindows_version_probe(ip)
		fmt.Println(err)
		return
	}
	n, err := conn.Read(reply)
	if err != nil || n < 36 {
		err = TmpWindows_version_probe(ip)
		fmt.Println(err)
		return
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		// status != 0
		fmt.Printf("can't determine whether %s is vulnerable or not\n", ip)
		//var Err = errors.New("can't determine whether target is vulnerable or not")
		err = TmpWindows_version_probe(ip)
		fmt.Println(err)
		return
	}

	// extract OS info
	var os string
	sessionSetupResponse := reply[36:n]
	if wordCount := sessionSetupResponse[0]; wordCount != 0 {
		// find byte count
		byteCount := binary.LittleEndian.Uint16(sessionSetupResponse[7:9])
		if n != int(byteCount)+45 {
			fmt.Println("[-]", ip+":445", "ms17010 invalid session setup AndX response")
		} else {
			// two continous null bytes indicates end of a unicode string
			for i := 10; i < len(sessionSetupResponse)-1; i++ {
				if sessionSetupResponse[i] == 0 && sessionSetupResponse[i+1] == 0 {
					os = string(sessionSetupResponse[10:i])
					os = strings.Replace(os, string([]byte{0x00}), "", -1)
					break
				}
			}
		}

	}
	userID := reply[32:34]
	treeConnectRequest[32] = userID[0]
	treeConnectRequest[33] = userID[1]
	// TODO change the ip in tree path though it doesn't matter
	_, err = conn.Write(treeConnectRequest)
	if err != nil {
		err = TmpWindows_version_probe(ip)
		fmt.Println(err)
		return
	}
	if n, err := conn.Read(reply); err != nil || n < 36 {
		err = TmpWindows_version_probe(ip)
		fmt.Println(err)
		return
	}

	treeID := reply[28:30]
	transNamedPipeRequest[28] = treeID[0]
	transNamedPipeRequest[29] = treeID[1]
	transNamedPipeRequest[32] = userID[0]
	transNamedPipeRequest[33] = userID[1]

	_, err = conn.Write(transNamedPipeRequest)
	if err != nil {
		err = TmpWindows_version_probe(ip)
		fmt.Println(err)
		return
	}
	if n, err := conn.Read(reply); err != nil || n < 36 {
		err = TmpWindows_version_probe(ip)
		fmt.Println(err)
		return
	}
	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		//fmt.Printf("%s\tMS17-010\t(%s)\n", ip, os)
		//if runtime.GOOS=="windows" {fmt.Printf("%s\tMS17-010\t(%s)\n", ip, os)
		//} else{fmt.Printf("\033[33m%s\tMS17-010\t(%s)\033[0m\n", ip, os)}
		result := fmt.Sprintf("[+] MS17-010 %s\t(%s)", ip, os)
		common.LogSuccess(result)
		defer func() {
			if common.SC != "" {
				//MS17010EXP(info)
			}
		}()
		// detect present of DOUBLEPULSAR SMB implant
		trans2SessionSetupRequest[28] = treeID[0]
		trans2SessionSetupRequest[29] = treeID[1]
		trans2SessionSetupRequest[32] = userID[0]
		trans2SessionSetupRequest[33] = userID[1]

		_, err = conn.Write(trans2SessionSetupRequest)
		if err != nil {
			err = TmpWindows_version_probe(ip)
			fmt.Println(err)
			return
		}
		if n, err := conn.Read(reply); err != nil || n < 36 {
			err = TmpWindows_version_probe(ip)
			fmt.Println(err)
			return
		}

		if reply[34] == 0x51 {
			result := fmt.Sprintf("[+] MS17-010 %s has DOUBLEPULSAR SMB IMPLANT", ip)
			common.LogSuccess(result)
			is_os_probe__success = true
		}

	} else {
		result := fmt.Sprintf("[*] OsInfo %s\t(%s)", ip, os)
		common.LogSuccess(result)
		is_os_probe__success = true
	}

	if is_os_probe__success == false {
		TmpWindows_version_probe(ip)
	}

}
