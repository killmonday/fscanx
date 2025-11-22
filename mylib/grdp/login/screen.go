package login

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"github.com/killmonday/fscanx/mylib/grdp/core"
	"github.com/killmonday/fscanx/mylib/grdp/glog"
	"github.com/killmonday/fscanx/mylib/grdp/protocol/nla"
	"github.com/killmonday/fscanx/mylib/grdp/protocol/pdu"
	"github.com/killmonday/fscanx/mylib/grdp/protocol/rfb"
	"github.com/killmonday/fscanx/mylib/grdp/protocol/sec"
	"github.com/killmonday/fscanx/mylib/grdp/protocol/t125"
	"github.com/killmonday/fscanx/mylib/grdp/protocol/tpkt"
	"github.com/killmonday/fscanx/mylib/grdp/protocol/x224"
	"golang.org/x/net/context"
	"golang.org/x/net/proxy"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	Socks5Proxy string     = ""
	LogLever    glog.LEVEL = glog.NONE
	OutputDir   string
)

func init() {
}

func RdpConn(host, domain, user, password string, timeout int64, rdpProtocol uint32) (bool, error) {
	g := NewClient(host, LogLever)
	status, err, reconnectProtocol := g.ScreenShot(domain, user, password, timeout, rdpProtocol)
	if status == true {
		return true, err
	} else {
		if reconnectProtocol != rdpProtocol {
			glog.Info("reconnect with protocol:", reconnectProtocol)
			return RdpConn(host, domain, user, password, timeout, reconnectProtocol)
		} else {
			return status, err
		}
	}
}

func RdpCrack(host, domain, user, password string, timeout int64, rdpProtocol uint32) (bool, error) {
	g := NewClient(host, LogLever)
	status, err, reconnectProtocol := g.Crack(domain, user, password, timeout, rdpProtocol)
	if status == true {
		return true, err
	} else {
		if reconnectProtocol != rdpProtocol {
			glog.Info("reconnect with protocol:", reconnectProtocol)
			return RdpCrack(host, domain, user, password, timeout, reconnectProtocol)
		} else {
			return status, err
		}
	}
}

type Client struct {
	Host string // ip:port
	tpkt *tpkt.TPKT
	x224 *x224.X224
	mcs  *t125.MCSClient
	sec  *sec.Client
	pdu  *pdu.Client
	vnc  *rfb.RFB
}

func NewClient(host string, logLevel glog.LEVEL) *Client {
	glog.SetLevel(logLevel)
	logger := log.New(os.Stdout, "", 0)
	glog.SetLogger(logger)
	return &Client{
		Host: host,
	}
}

func WrapperTcpWithTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	local_ip := "0.0.0.0"
	net_ip := net.ParseIP(local_ip)
	if net_ip == nil {
		net_ip = net.ParseIP("0.0.0.0")
	}
	local_addr := &net.TCPAddr{
		IP: net_ip, // 替换为你想要使用的本地IP地址
	}
	d := &net.Dialer{Timeout: timeout, LocalAddr: local_addr}
	return WrapperTCP(network, address, d)
}

func WrapperTCP(network, address string, forward *net.Dialer) (net.Conn, error) {
	//get conn
	var conn net.Conn
	if Socks5Proxy == "" {
		var err error
		conn, err = forward.Dial(network, address)
		if err != nil {
			return nil, err
		}
	} else {
		dailer, err := Socks5Dailer(forward)
		if err != nil {
			return nil, err
		}
		conn, err = dailer.Dial(network, address)
		if err != nil {
			// fmt.Println(err)
			return nil, err
		}

	}

	timeout := forward.Timeout
	if err := conn.SetWriteDeadline(time.Now().Add(timeout * 6)); err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout * 6)); err != nil {
		return nil, err
	}

	return conn, nil

}

func Socks5Dailer(forward *net.Dialer) (proxy.Dialer, error) {
	u, err := url.Parse(Socks5Proxy)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(u.Scheme) != "socks5" {
		return nil, errors.New("Only support socks5")
	}
	address := u.Host
	var auth proxy.Auth
	var dailer proxy.Dialer
	if u.User.String() != "" {
		auth = proxy.Auth{}
		auth.User = u.User.Username()
		password, _ := u.User.Password()
		auth.Password = password
		dailer, err = proxy.SOCKS5("tcp", address, &auth, forward)
	} else {
		dailer, err = proxy.SOCKS5("tcp", address, nil, forward)
	}

	if err != nil {
		return nil, err
	}
	return dailer, nil
}

type Bitmap struct {
	DestLeft     int    `json:"destLeft"`
	DestTop      int    `json:"destTop"`
	DestRight    int    `json:"destRight"`
	DestBottom   int    `json:"destBottom"`
	Width        int    `json:"width"`
	Height       int    `json:"height"`
	BitsPerPixel int    `json:"bitsPerPixel"`
	IsCompress   bool   `json:"isCompress"`
	Data         []byte `json:"data"`
}

func Bpp(BitsPerPixel uint16) (pixel int) {
	switch BitsPerPixel {
	case 15:
		pixel = 1

	case 16:
		pixel = 2

	case 24:
		pixel = 3

	case 32:
		pixel = 4

	default:
		glog.Error("-------------------------------------Bpp func. invalid bitmap data format")
	}
	return
}

func BitmapDecompress(bitmap *pdu.BitmapData) []byte {
	return core.Decompress(bitmap.BitmapDataStream, int(bitmap.Width), int(bitmap.Height), Bpp(bitmap.BitsPerPixel))
}

func ToRGBA(pixel int, i int, data []byte) (r, g, b, a uint8) {
	a = 255
	switch pixel {
	case 1:
		rgb555 := core.Uint16BE(data[i], data[i+1])
		r, g, b = core.RGB555ToRGB(rgb555)
	case 2:
		rgb565 := core.Uint16BE(data[i], data[i+1])
		r, g, b = core.RGB565ToRGB(rgb565)
	case 3, 4:
		fallthrough
	default:
		r, g, b = data[i+2], data[i+1], data[i]
	}

	return
}

func (g *Client) ProbeOSInfo(host, domain, user, pwd string, timeout int64, rdpProtocol uint32) (info map[string]any) {
	start := time.Now()
	exitFlag := make(chan bool)
	info = make(map[string]any)

	targetSlice := strings.Split(g.Host, ":")
	ip := targetSlice[0]
	conn, err := WrapperTcpWithTimeout("tcp", g.Host, time.Duration(timeout)*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	glog.Info(conn.LocalAddr().String())

	g.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, pwd))
	g.x224 = x224.New(g.tpkt)
	g.mcs = t125.NewMCSClient(g.x224)
	g.sec = sec.NewClient(g.mcs)
	g.pdu = pdu.NewClient(g.sec)

	g.sec.SetUser(user)
	g.sec.SetPwd(pwd)
	g.sec.SetDomain(domain)

	g.tpkt.SetFastPathListener(g.sec)
	g.sec.SetFastPathListener(g.pdu)
	g.pdu.SetFastPathSender(g.tpkt)
	g.sec.SetChannelSender(g.mcs)

	g.tpkt.On("os_info", func(infoMap map[string]any) {
		glog.Debug("[+] callback, get os info ........................")
		for k, v := range infoMap {
			glog.Debug("%s: %s\n", k, v)
		}
		info = infoMap
		g.pdu.Emit("done")
	})

	g.x224.SetRequestedProtocol(rdpProtocol) //x224.PROTOCOL_SSL , x224.PROTOCOL_RDP , x224.PROTOCOL_HYBRID , x224.PROTOCOL_HYBRID_EX
	g.x224.On("reconnect", func(protocol uint32) {
		info["reconn"] = protocol
		g.pdu.Emit("close")
		exitFlag <- true
	})

	err = g.x224.Connect()
	if err != nil {
		info["err"] = err.Error()
		return
	}
	glog.Info("wait connect ok")

	g.pdu.On("error", func(e error) {
		err = e
		glog.Error("error", e)
		g.pdu.Emit("done")
	})
	g.pdu.On("close", func() {
		err = errors.New("close")
		glog.Info("on close")
		g.pdu.Emit("done")
	})
	g.pdu.On("success", func() {
		glog.Debugf("===============login success %s===============", ip)
		err = nil
		g.pdu.Emit("done")
	})
	g.pdu.On("ready", func() {
		err = nil
		glog.Debug("on ready")
	})
	g.pdu.On("bitmap", func(rectangles []pdu.BitmapData) {
	})
	g.pdu.On("done", func() {
		glog.Debug("done信号触发")
		exitFlag <- true
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout*3)*time.Second)
	defer cancel()

loop:
	for {
		select {
		case <-time.After(time.Second * time.Duration(timeout)): //
			break loop
		case <-exitFlag:
			break loop
		case <-ctx.Done():
			glog.Debug("总超时已达到，退出")
			break loop
		}
	}
	glog.Debug("循环结束，总时间过去了：", time.Since(start))
	return info
}

func (g *Client) ScreenShot(domain, user, pwd string, timeout int64, rdpProtocol uint32) (status bool, err error, reconnProtocol uint32) {
	//glog.SetLevel(glog.ERROR)
	reconnProtocol = rdpProtocol
	pic_length := 1280 //1280
	pic_width := 800   //800
	needReconnect := false
	isScreenOK := false
	refresh := make(chan bool)
	exitFlag := make(chan bool)
	start := time.Now()
	now := start
	screenImage := image.NewRGBA(image.Rect(0, 0, pic_length, pic_width))

	index := 1
	targetSlice := strings.Split(g.Host, ":")
	ip := targetSlice[0]
	port := targetSlice[1]
	status = false
	conn, err := WrapperTcpWithTimeout("tcp", g.Host, time.Duration(timeout)*time.Second)
	if err != nil {
		return status, fmt.Errorf("[dial err] %v", err), reconnProtocol
	}
	defer conn.Close()
	glog.Info(conn.LocalAddr().String())

	g.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, pwd))
	g.x224 = x224.New(g.tpkt)
	g.mcs = t125.NewMCSClient(g.x224)
	g.sec = sec.NewClient(g.mcs)
	g.pdu = pdu.NewClient(g.sec)

	g.sec.SetUser(user)
	g.sec.SetPwd(pwd)
	g.sec.SetDomain(domain)
	//g.sec.SetClientAutoReconnect()

	g.tpkt.SetFastPathListener(g.sec)
	g.sec.SetFastPathListener(g.pdu)
	g.pdu.SetFastPathSender(g.tpkt)
	g.sec.SetChannelSender(g.mcs)

	g.tpkt.On("os_info", func(info map[string]any) {
		glog.Debug("[+] callback, get os info ........................")
		for k, v := range info {
			glog.Debug("%s: %s\n", k, v)
		}
	})

	g.x224.SetRequestedProtocol(rdpProtocol) //x224.PROTOCOL_SSL , x224.PROTOCOL_RDP , x224.PROTOCOL_HYBRID , x224.PROTOCOL_HYBRID_EX
	g.x224.On("reconnect", func(protocol uint32) {
		needReconnect = true
		reconnProtocol = protocol
		glog.Info("need reconnect with protocol:", protocol)
		g.pdu.Emit("close")
		exitFlag <- true
	})
	g.x224.On("more_timeout", func() {
		timeout += 18 //如果是PROTOCOL_RDP协议，可以适当延长超时时间
	})

	err = g.x224.Connect()
	if err != nil {
		return status, fmt.Errorf("[x224 connect err] %v", err), reconnProtocol
	}
	glog.Info("wait connect ok")

	g.pdu.On("error", func(e error) {
		err = e
		glog.Error("error", e)
		g.pdu.Emit("done")
	})
	g.pdu.On("close", func() {
		err = errors.New("close")
		glog.Info("on close")
		g.pdu.Emit("done")
	})
	g.pdu.On("success", func() {
		glog.Debugf("===============login success %s===============", ip)
		status = true
		err = nil
		g.pdu.Emit("done")
	})
	g.pdu.On("ready", func() {
		err = nil
		glog.Debug("on ready")
		//g.pdu.Emit("done")
	})
	g.pdu.On("bitmap", func(rectangles []pdu.BitmapData) {
		now = time.Now()
		// 发送一个鼠标事件，作用是与服务器保持联系不要断开
		rand.New(rand.NewSource(time.Now().UnixNano()))
		randomNumber := rand.Intn(1000) + 10 // 10到1000之间的随机数
		mouseX := 60 + randomNumber
		mouseY := 10 + randomNumber
		pevent := &pdu.PointerEvent{}
		pevent.PointerFlags |= pdu.PTRFLAGS_MOVE
		pevent.XPos = uint16(mouseX)
		pevent.YPos = uint16(mouseY)
		g.pdu.SendInputEvents(pdu.INPUT_EVENT_MOUSE, []pdu.InputEventsInterface{pevent})

		glog.Debug("on update bitmap:", len(rectangles))
		bs := make([]Bitmap, 0)
		for _, v := range rectangles {
			IsCompress := v.IsCompress()
			data := v.BitmapDataStream
			if IsCompress {
				data = BitmapDecompress(&v)
				IsCompress = false
			}
			b := Bitmap{int(v.DestLeft), int(v.DestTop), int(v.DestRight), int(v.DestBottom),
				int(v.Width), int(v.Height), Bpp(v.BitsPerPixel), IsCompress, data}
			bs = append(bs, b)
		}
		var (
			pixel      int
			i          int
			r, g, b, a uint8
		)

		for _, bm := range bs {
			i = 0
			pixel = bm.BitsPerPixel
			m := image.NewRGBA(image.Rect(0, 0, bm.Width, bm.Height))
			for y := 0; y < bm.Height; y++ {
				for x := 0; x < bm.Width; x++ {
					r, g, b, a = ToRGBA(pixel, i, bm.Data)
					c := color.RGBA{R: r, G: g, B: b, A: a}
					i += pixel
					m.Set(x, y, c)
				}
			}
			draw.Draw(screenImage, screenImage.Bounds().Add(image.Pt(bm.DestLeft, bm.DestTop)), m, m.Bounds().Min, draw.Src)
		}
		// Encode to jpeg.
		//var imageBuf bytes.Buffer
		//err = jpeg.Encode(&imageBuf, screenImage, nil)
		//
		//if err != nil {
		//	glog.Info("trans bitmap to jpeg err:", err)
		//}

		// Write to file.
		//fo, err := os.Create(fmt.Sprintf("img/%s-%d.jpg", ip, index))
		//if err != nil {
		//	panic(err)
		//}
		//index += 1
		//fw := bufio.NewWriter(fo)
		//fw.Write(imageBuf.Bytes())

		isScreenOK = true
		refresh <- true

	})
	g.pdu.On("done", func() {
		glog.Debug("done信号触发")
		exitFlag <- true
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout*6)*time.Second)
	defer cancel()

loop:
	for {
		select {
		case <-time.After(time.Second * time.Duration(timeout*3)): //
			glog.Debug("本次获取bitmap超时了, 距离上次获取到图像过去了：", time.Since(now))
			break loop
		case <-refresh:
			continue loop
		case <-exitFlag:
			break loop
		case <-ctx.Done():
			glog.Debug("总超时已达到，退出")
			break loop
		}
	}
	glog.Debug("循环结束，总时间过去了：", time.Since(start))

	if g.x224.ServerChooseProtocol() == x224.PROTOCOL_HYBRID && g.x224.ServerChooseProtocol() == x224.PROTOCOL_HYBRID {
		if err == nil {
			status = true
		}
	}

	if needReconnect {
		return status, err, reconnProtocol
	} else if isScreenOK {
		glog.Info("get screen ok")
		// Encode to jpeg.
		var imageBuf bytes.Buffer
		err = jpeg.Encode(&imageBuf, screenImage, nil)

		if err != nil {
			log.Panic(err)
		}

		// Write to file.
		saveDate := time.Now().Format("2006_01_02_15_04_05")
		fo, writeErr := os.Create(fmt.Sprintf("%s/%s_%s_%s.jpg", OutputDir, ip, port, saveDate))
		index += 1
		if writeErr != nil {
			glog.Error("Can not create rdp screenshot file:", writeErr)
		} else {
			fw := bufio.NewWriter(fo)
			_, writeErr := fw.Write(imageBuf.Bytes())
			if writeErr != nil {
				glog.Error("Can not write rdp screenshot file:", writeErr)
			}
		}

	}
	return status, err, reconnProtocol

}

func (g *Client) Crack(domain, user, pwd string, timeout int64, rdpProtocol uint32) (status bool, err error, reconnProtocol uint32) {
	//glog.SetLevel(glog.ERROR)
	reconnProtocol = rdpProtocol
	needReconnect := false
	refresh := make(chan bool)
	exitFlag := make(chan bool)
	start := time.Now()
	now := start

	targetSlice := strings.Split(g.Host, ":")
	ip := targetSlice[0]
	status = false
	conn, err := WrapperTcpWithTimeout("tcp", g.Host, time.Duration(timeout)*time.Second)
	if err != nil {
		return status, fmt.Errorf("[dial err] %v", err), reconnProtocol
	}
	defer conn.Close()
	glog.Info(conn.LocalAddr().String())

	g.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, pwd))
	g.x224 = x224.New(g.tpkt)
	g.mcs = t125.NewMCSClient(g.x224)
	g.sec = sec.NewClient(g.mcs)
	g.pdu = pdu.NewClient(g.sec)

	g.sec.SetUser(user)
	g.sec.SetPwd(pwd)
	g.sec.SetDomain(domain)
	//g.sec.SetClientAutoReconnect()

	g.tpkt.SetFastPathListener(g.sec)
	g.sec.SetFastPathListener(g.pdu)
	g.pdu.SetFastPathSender(g.tpkt)
	g.sec.SetChannelSender(g.mcs)

	g.tpkt.On("os_info", func(info map[string]any) {
		glog.Debug("[+] callback, get os info ........................")
		for k, v := range info {
			glog.Debug("%s: %s\n", k, v)
		}
	})

	g.x224.SetRequestedProtocol(rdpProtocol) //x224.PROTOCOL_SSL , x224.PROTOCOL_RDP , x224.PROTOCOL_HYBRID , x224.PROTOCOL_HYBRID_EX
	g.x224.On("reconnect", func(protocol uint32) {
		needReconnect = true
		reconnProtocol = protocol
		glog.Info("need reconnect with protocol:", protocol)
		g.pdu.Emit("close")
		exitFlag <- true
	})
	g.x224.On("more_timeout", func() {
		timeout += 18 //如果是PROTOCOL_RDP协议，可以适当延长超时时间
	})

	err = g.x224.Connect()
	if err != nil {
		return status, fmt.Errorf("[x224 connect err] %v", err), reconnProtocol
	}
	glog.Info("wait connect ok")

	g.pdu.On("error", func(e error) {
		err = e
		glog.Error("error", e)
		g.pdu.Emit("done")
	})
	g.pdu.On("close", func() {
		err = errors.New("close")
		glog.Info("on close")
		g.pdu.Emit("done")
	})
	g.pdu.On("success", func() {
		glog.Debugf("===============login success %s===============", ip)
		status = true
		err = nil
		g.pdu.Emit("done")
	})
	g.pdu.On("ready", func() {
		err = nil
		glog.Debug("on ready")
		//g.pdu.Emit("done")
	})
	g.pdu.On("bitmap", func(rectangles []pdu.BitmapData) {
		now = time.Now()
		// 发送一个鼠标事件，作用是与服务器保持联系不要断开
		rand.New(rand.NewSource(time.Now().UnixNano()))
		randomNumber := rand.Intn(1000) + 10 // 10到1000之间的随机数
		mouseX := 60 + randomNumber
		mouseY := 10 + randomNumber
		pevent := &pdu.PointerEvent{}
		pevent.PointerFlags |= pdu.PTRFLAGS_MOVE
		pevent.XPos = uint16(mouseX)
		pevent.YPos = uint16(mouseY)
		g.pdu.SendInputEvents(pdu.INPUT_EVENT_MOUSE, []pdu.InputEventsInterface{pevent})

		glog.Debug("on update bitmap:", len(rectangles))
		refresh <- true

	})
	g.pdu.On("done", func() {
		glog.Debug("done信号触发")
		exitFlag <- true
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout*6)*time.Second)
	defer cancel()

loop:
	for {
		select {
		case <-time.After(time.Second * time.Duration(timeout*3)): //
			glog.Debug("本次获取bitmap超时了, 距离上次获取到图像过去了：", time.Since(now))
			break loop
		case <-refresh:
			continue loop
		case <-exitFlag:
			break loop
		case <-ctx.Done():
			glog.Debug("总超时已达到，退出")
			break loop
		}
	}
	glog.Debug("循环结束，总时间过去了：", time.Since(start))

	if g.x224.ServerChooseProtocol() == x224.PROTOCOL_HYBRID && g.x224.ServerChooseProtocol() == x224.PROTOCOL_HYBRID {
		if err == nil {
			status = true
		}
	}

	if needReconnect {
		return status, err, reconnProtocol
	}
	return status, err, reconnProtocol
}
