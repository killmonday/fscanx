package Plugins

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/xxx/wscan/common"
)

var (
	negotiateProtocolRequest_enc     = "G8o+kd/4y8chPCaObKK8L9+tJVFBb7ntWH/EXJ74635V3UTXA4TFOc6uabZfuLr0Xisnk7OsKJZ2Xdd3l8HNLdMOYZXAX5ZXnMC4qI+1d/MXA2TmidXeqGt8d9UEF5VesQlhP051GGBSldkJkVrP/fzn4gvLXcwgAYee3Zi2opAvuM6ScXrMkcbx200ThnOOEx98/7ArteornbRiXQjnr6dkJEUDTS43AW6Jl3OK2876Yaz5iYBx+DW5WjiLcMR+b58NJRxm4FlVpusZjBpzEs4XOEqglk6QIWfWbFZYgdNLy3WaFkkgDjmB1+6LhpYSOaTsh4EM0rwZq2Z4Lr8TE5WcPkb/JNsWNbibKlwtNtp94fIYvAWgxt5mn/oXpfUD"
	sessionSetupRequest_enc          = "52HeCQEbsSwiSXg98sdD64qyRou0jARlvfQi1ekDHS77Nk/8dYftNXlFahLEYWIxYYJ8u53db9OaDfAvOEkuox+p+Ic1VL70r9Q5HuL+NMyeyeN5T5el07X5cT66oBDJnScs1XdvM6CBRtj1kUs2h40Z5Vj9EGzGk99SFXjSqbtGfKFBp0DhL5wPQKsoiXYLKKh9NQiOhOMWHYy/C+Iwhf3Qr8d1Wbs2vgEzaWZqIJ3BM3z+dhRBszQoQftszC16TUhGQc48XPFHN74VRxXgVe6xNQwqrWEpA4hcQeF1+QqRVHxuN+PFR7qwEcU1JbnTNISaSrqEe8GtRo1r2rs7+lOFmbe4qqyUMgHhZ6Pwu1bkhrocMUUzWQBogAvXwFb8"
	treeConnectRequest_enc           = "+b/lRcmLzH0c0BYhiTaYNvTVdYz1OdYYDKhzGn/3T3P4b6pAR8D+xPdlb7O4D4A9KMyeIBphDPmEtFy44rtto2dadFoit350nghebxbYA0pTCWIBd1kN0BGMEidRDBwLOpZE6Qpph/DlziDjjfXUz955dr0cigc9ETHD/+f3fELKsopTPkbCsudgCs48mlbXcL13GVG5cGwKzRuP4ezcdKbYzq1DX2I7RNeBtw/vAlYh6etKLv7s+YyZ/r8m0fBY9A57j+XrsmZAyTWbhPJkCg=="
	transNamedPipeRequest_enc        = "k/RGiUQ/tw1yiqioUIqirzGC1SxTAmQmtnfKd1qiLish7FQYxvE+h4/p7RKgWemIWRXDf2XSJ3K0LUIX0vv1gx2eb4NatU7Qosnrhebz3gUo7u25P5BZH1QKdagzPqtitVjASpxIjB3uNWtYMrXGkkuAm8QEitberc+mP0vnzZ8Nv/xiiGBko8O4P/wCKaN2KZVDLbv2jrN8V/1zY6fvWA=="
	trans2SessionSetupRequest_enc    = "JqNw6PUKcWOYFisUoUCyD24wnML2Yd8kumx9hJnFWbhM2TQkRvKHsOMWzPVfggRrLl8sLQFqzk8bv8Rpox3uS61l480Mv7HdBPeBeBeFudZMntXBUa4pWUH8D9EXCjoUqgAdvw6kGbPOOKUq3WmNb0GDCZapqQwyUKKMHmNIUMVMAOyVfKeEMJA6LViGwyvHVMNZ1XWLr0xafKfEuz4qoHiDyVWomGjJt8DQd6+jgLk="
	negotiateProtocolRequest, _      = hex.DecodeString(AesDecrypt(negotiateProtocolRequest_enc, key))
	sessionSetupRequest, _           = hex.DecodeString(AesDecrypt(sessionSetupRequest_enc, key))
	treeConnectRequest, _            = hex.DecodeString(AesDecrypt(treeConnectRequest_enc, key))
	transNamedPipeRequest, _         = hex.DecodeString(AesDecrypt(transNamedPipeRequest_enc, key))
	trans2SessionSetupRequest, _     = hex.DecodeString(AesDecrypt(trans2SessionSetupRequest_enc, key))
	smb2_negotiateProtocolRequest, _ = hex.DecodeString("00000045ff534d4272000000001853c8000000000000000000000000fffffffe00000000002200024e54204c4d20302e31320002534d4220322e3030320002534d4220322e3f3f3f00")
	smb2_query1, _                   = hex.DecodeString("000000e8fe534d4240000000000000000000000000000000000000000100000000000000fffe00000000000000000000000000000000000000000000000000000000000024000500010000007f000000a7225731d903ec1192653c58c275acfa70000000040000000202100200030203110300000100260000000000010020000100064115a29b6f7a8fdaa7e9f3eda8103188749e53aff79236388d99e60a274b8400000200060000000000020002000100000003001000000000000400000001000000040002000300010005001800000000003100390032002e003100360038002e0036002e0036003000")
	smb2_query2, _                   = hex.DecodeString("000000a2fe534d4240000100000000000100210010000000000000000200000000000000fffe00000000000000000000000000000000000000000000000000000000000019000001010000000000000058004a000000000000000000604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000978208e2000000000000000000000000000000000a00614a0000000f")
	smb2_new_q1, _                   = hex.DecodeString("00000085ff534d4272000000001853c80000000000000000000000000000fffe00000000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
	smb2_new_q2, _                   = hex.DecodeString("0000010aff534d4273000000001807c80000000000000000000000000000fffe000040000cff000a01044132000000000000004a0000000000d40000a0cf00604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000078208a2000000000000000000000000000000000502ce0e0000000f00570069006e0064006f0077007300200053006500720076006500720020003200300030003300200033003700390030002000530065007200760069006300650020005000610063006b002000320000000000570069006e0064006f0077007300200053006500720076006500720020003200300030003300200035002e00320000000000")
)

func LittleEndUtf16ToUtf8Str(input []byte) (utf8Str string) {
	// 将大端字节数组转换为UTF-16编码的码点序列
	var utf16Data []uint16
	buf := bytes.NewReader(input)
	for {
		var u16 uint16
		err := binary.Read(buf, binary.LittleEndian, &u16) //因为输入的buf是小端序的字节串，所以这里要指定以小端序来读取，并赋值到u16变量
		if err != nil {
			break
		}
		utf16Data = append(utf16Data, u16)
	}

	// 将UTF-16码点序列转换为UTF-8编码的字节序列
	utf8Data := utf16.Decode(utf16Data)

	// 将UTF-8字节序列转换为字符串
	utf8Str = string(utf8Data)
	return
}

func MS17010(info *common.HostInfo) error {
	// if common.DoBrute {
	// 	return nil
	// }
	err := MS17010Scan(info)
	if err != nil {
		errlog := fmt.Sprintf("[-] Ms17010 %v %v", info.Host, err)
		common.LogError(errlog)
	}
	return err
}

func MS17010Scan(info *common.HostInfo) error {
	is_os_probe__success := false
	ip := info.Host
	// connecting to a host in LAN if reachable should be very quick
	conn, err := common.WrapperTcpWithTimeout("tcp", ip+":445", time.Duration(common.TcpTimeout)*time.Second*4)
	if err != nil {
		//fmt.Printf("failed to connect to %s\n", ip)
		return err
	}
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Duration(common.TcpTimeout) * time.Second * 4))
	if err != nil {
		//fmt.Printf("failed to connect to %s\n", ip)
		return err
	}
	_, err = conn.Write(negotiateProtocolRequest)
	if err != nil {
		return windows_version_probe(ip)
	}
	reply := make([]byte, 1024)
	// let alone half packet
	if n, err := conn.Read(reply); err != nil || n < 36 {
		//fmt.Printf("failed to read 1 to %s, err: %v\n", ip, err)
		return windows_version_probe(ip)
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		// status != 0
		return windows_version_probe(ip)
	}

	_, err = conn.Write(sessionSetupRequest)
	if err != nil {
		return windows_version_probe(ip)
	}
	n, err := conn.Read(reply)
	if err != nil || n < 36 {
		return windows_version_probe(ip)
	}

	if binary.LittleEndian.Uint32(reply[9:13]) != 0 {
		// status != 0
		common.LogSuccess("[-] smb can't determine whether %s is vulnerable or not\n", ip)
		//var Err = errors.New("can't determine whether target is vulnerable or not")
		return windows_version_probe(ip)
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
		return windows_version_probe(ip)
	}
	if n, err := conn.Read(reply); err != nil || n < 36 {
		return windows_version_probe(ip)
	}

	treeID := reply[28:30]
	transNamedPipeRequest[28] = treeID[0]
	transNamedPipeRequest[29] = treeID[1]
	transNamedPipeRequest[32] = userID[0]
	transNamedPipeRequest[33] = userID[1]

	_, err = conn.Write(transNamedPipeRequest)
	if err != nil {
		return windows_version_probe(ip)
	}
	if n, err := conn.Read(reply); err != nil || n < 36 {
		return windows_version_probe(ip)
	}

	if reply[9] == 0x05 && reply[10] == 0x02 && reply[11] == 0x00 && reply[12] == 0xc0 {
		//fmt.Printf("%s\tMS17-010\t(%s)\n", ip, os)
		//if runtime.GOOS=="windows" {fmt.Printf("%s\tMS17-010\t(%s)\n", ip, os)
		//} else{fmt.Printf("\033[33m%s\tMS17-010\t(%s)\033[0m\n", ip, os)}
		result := fmt.Sprintf("[+] MS17-010 %s\t(%s)", ip, os)
		common.LogSuccess(result)
		defer func() {
			if common.SC != "" {
				MS17010EXP(info)
			}
		}()
		// detect present of DOUBLEPULSAR SMB implant
		trans2SessionSetupRequest[28] = treeID[0]
		trans2SessionSetupRequest[29] = treeID[1]
		trans2SessionSetupRequest[32] = userID[0]
		trans2SessionSetupRequest[33] = userID[1]

		_, err = conn.Write(trans2SessionSetupRequest)
		if err != nil {
			return windows_version_probe(ip)
		}
		if n, err := conn.Read(reply); err != nil || n < 36 {
			return windows_version_probe(ip)
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
		windows_version_probe(ip)
	}

	return err
}

func windows_version_probe(ip string) error {
	conn_smb2_methodA, err := common.WrapperTcpWithTimeout("tcp", ip+":445", time.Duration(common.TcpTimeout)*time.Second*3)
	if err != nil {
		//fmt.Printf("failed to connect to %s\n", ip)
		return err
	}
	defer conn_smb2_methodA.Close()
	err = conn_smb2_methodA.SetDeadline(time.Now().Add(time.Duration(common.TcpTimeout) * time.Second * 3))
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
		conn_smb2_methodB, err := common.WrapperTcpWithTimeout("tcp", ip+":445", time.Duration(common.TcpTimeout)*time.Second*3)
		if err != nil {
			//fmt.Printf("failed to connect to %s\n", ip)
			return err
		}
		defer conn_smb2_methodB.Close()
		err = conn_smb2_methodB.SetDeadline(time.Now().Add(time.Duration(common.TcpTimeout) * time.Second * 3))
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
		//err = conn_smb2_methodB.SetDeadline(time.Now().Add(time.Duration(common.TcpTimeout) * time.Second * 3))
		if err != nil {
			//fmt.Printf("failed to connect to %s\n", ip)
			return err
		}
		_, err = conn_smb2_methodB.Read(rep_byte)
		if err != nil {
			//fmt.Println("fail to read x2:", err)
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
					//fmt.Println("item=", item)
					utf8Str := LittleEndUtf16ToUtf8Str(item)
					//fmt.Printf("[*] get %s = %s\n", itemName, utf8Str)
					if itemName == "NetBiosDomainName" {
						netbiosDomainName = utf8Str
					}
					if itemName == "DomainName" {
						dnsDomainName = utf8Str
					}
					if itemName == "ComputerName" {
						FQDN = utf8Str
					}
				}
			}
			domainInfo := "[WORKGROUP]"
			if netbiosDomainName != dnsDomainName && netbiosDomainName != FQDN {
				domainInfo = fmt.Sprintf("[%s] [%s] [%s]", netbiosDomainName, dnsDomainName, FQDN)
			}
			common.LogSuccess(result + domainInfo + "\n")
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
		result := fmt.Sprintf("[*] OsInfo %s\t(W%s)", ip, clean_str)

		ntlmFlag := []byte("NTLMSSP")
		start := bytes.Index(reponse_byte, ntlmFlag) // 查找字节串的位置

		netbiosDomainName, dnsDomainName, FQDN := "None", "None", "None"
		if start != -1 {
			//fmt.Printf("Found 'NTLMSSP' at position: %d\n", start)
			for payload, itemName := range NetBIOS_ITEM_TYPE {
				new_buffer := reponse_byte[start+7+6:]
				netbios_postion := bytes.Index(new_buffer, []byte(payload))
				//fmt.Println("netbios_postion=", netbios_postion)
				itemLen := int(new_buffer[netbios_postion+2])
				//fmt.Println("itemLen=", itemLen)
				item := new_buffer[netbios_postion+2+1+1 : netbios_postion+2+1+1+itemLen]
				//fmt.Println("item=", item)
				utf8Str := LittleEndUtf16ToUtf8Str(item)
				//fmt.Printf("[*] get %s = %s\n", itemName, utf8Str)
				if itemName == "NetBiosDomainName" {
					netbiosDomainName = utf8Str
				}
				if itemName == "DomainName" {
					dnsDomainName = utf8Str
				}
				if itemName == "ComputerName" {
					FQDN = utf8Str
				}
			}
		}
		domainInfo := "[WORKGROUP]"
		if netbiosDomainName != dnsDomainName && netbiosDomainName != FQDN {
			domainInfo = fmt.Sprintf("[%s] [%s] [%s]", netbiosDomainName, dnsDomainName, FQDN)
		}
		common.LogSuccess(result + domainInfo + "\n")
	}
	return err
}
