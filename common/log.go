package common

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

var Num int64
var End int64
var Results = make(chan *string)
var LogSucTime int64
var LogErrTime int64
var WaitTime int64
var Silent bool
var Nocolor bool
var JsonOutput bool
var LogWG sync.WaitGroup

type JsonText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func init() {
	log.SetOutput(io.Discard)
	LogSucTime = time.Now().Unix()
	go SaveLog()
}

//func LogSuccess(result string) {
//	LogWG.Add(1)
//	LogSucTime = time.Now().Unix()
//	Results <- &result
//}

func LogSuccess(formatStr string, a ...any) {
	LogWG.Add(1)
	LogSucTime = time.Now().Unix()
	if a != nil {
		printStr := fmt.Sprintf(formatStr, a...)
		Results <- &printStr
	} else {
		Results <- &formatStr
	}
}

func SaveLog() {
	var fl *os.File
	var ferr error
	if IsSave {
		fl, ferr = os.OpenFile(Outputfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if ferr != nil {
			fmt.Printf("Create %s error, %v\n", Outputfile, ferr)
		}
	}

	var colorFlag bool = true
	whiteStyle := color.New(color.FgWhite)
	yeStyleHi := color.New(color.FgHiYellow, color.Bold)
	cyanStyle := color.New(color.FgCyan)
	preTextStyle := color.New(color.FgWhite)

	for result := range Results {
		if !Silent {
			if Nocolor {
				fmt.Println(*result)
			} else {
				if strings.HasPrefix(*result, "[+] InfoScan") {
					color.Green(*result)
				} else if strings.HasPrefix(*result, "[+] Product") || strings.HasPrefix(*result, "[*] JUMP") {
					// fmt.Println(*result)
					// color.Cyan(*result)
					if colorFlag == true {
						//color.HiYellow(*result)
						if strings.HasPrefix(*result, "[+] Product") {
							slice := strings.Split(*result, "\t")
							preTextStyle.Print(slice[0] + "\t" + slice[1] + "\t")
							yeStyleHi.Print(slice[2] + "\t")
							whiteStyle.Println(strings.Join(slice[3:], "\t"))
						} else {
							color.White(*result)
						}

						colorFlag = false
					} else {
						if strings.HasPrefix(*result, "[+] Product") {
							slice := strings.Split(*result, "\t")
							preTextStyle.Print(slice[0] + "\t" + slice[1] + "\t")
							yeStyleHi.Print(slice[2] + "\t")
							cyanStyle.Println(strings.Join(slice[3:], "\t"))
						} else {
							color.Cyan(*result)
						}

						colorFlag = true
					}

				} else if strings.Index(*result, "rdpscan") != -1 {
					color.Yellow(*result)
				} else if strings.HasPrefix(*result, "[+]") {
					color.Red(*result)
				} else {
					fmt.Println(*result)
				}
			}
		}
		if IsSave {
			WriteFile(*result, fl)
		}
		LogWG.Done()
	}
	if fl != nil {
		fl.Close()
	}
}

func WriteFile(result string, fl *os.File) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[CRITICAL] WriteFile panic: %v\n", r)
		}
	}()
	var err error
	if JsonOutput {
		var scantype string
		var text string
		if strings.HasPrefix(result, "[+]") || strings.HasPrefix(result, "[*]") || strings.HasPrefix(result, "[-]") {
			//找到第二个空格的位置
			index := strings.Index(result[4:], " ")
			if index == -1 {
				scantype = "msg"
				text = result[4:]
			} else {
				scantype = result[4 : 4+index]
				text = result[4+index+1:]
			}
		} else {
			scantype = "msg"
			text = result
		}
		jsonText := JsonText{
			Type: scantype,
			Text: text,
		}
		jsonData, err := json.Marshal(jsonText)
		if err != nil {
			fmt.Println(err)
			jsonText = JsonText{
				Type: "msg",
				Text: result,
			}
			jsonData, err = json.Marshal(jsonText)
			if err != nil {
				fmt.Println(err)
				jsonData = []byte(result)
			}
		}
		jsonData = append(jsonData, []byte(",\n")...)
		_, err = fl.Write(jsonData)
	} else {
		_, err = fl.WriteString(result + "\n")
	}
	err = fl.Sync()
	if err != nil {
		fmt.Printf("Write log error, %v\n", err)
	}
}

func LogError(errinfo interface{}) {
	if WaitTime == 0 {
		//fmt.Printf("已完成 %v/%v %v \n", End, Num, errinfo)
	} else if (time.Now().Unix()-LogSucTime) > WaitTime && (time.Now().Unix()-LogErrTime) > WaitTime {
		//fmt.Printf("已完成 %v/%v %v \n", End, Num, errinfo)
		LogErrTime = time.Now().Unix()
	}
}

func CheckErrs(err error) bool {
	if err == nil {
		return false
	}
	errs := []string{
		"closed by the remote host", "too many connections",
		"i/o timeout", "EOF", "A connection attempt failed",
		"established connection failed", "connection attempt failed",
		"Unable to read", "is not allowed to connect to this",
		"no pg_hba.conf entry",
		"No connection could be made",
		"invalid packet size",
		"bad connection",
	}
	for _, key := range errs {
		if strings.Contains(strings.ToLower(err.Error()), strings.ToLower(key)) {
			return true
		}
	}
	return false
}
