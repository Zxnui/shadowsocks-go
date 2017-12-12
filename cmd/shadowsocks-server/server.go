package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

const (
	idType  = 0 // address type index
	idIP0   = 1 // ip addres start index
	idDmLen = 1 // domain address length index
	idDm0   = 2 // domain address start index

	typeIPv4 = 1 // type is ipv4 address
	typeDm   = 3 // type is domain address
	typeIPv6 = 4 // type is ipv6 address

	lenIPv4     = net.IPv4len + 2 // ipv4 + 2port
	lenIPv6     = net.IPv6len + 2 // ipv6 + 2port
	lenDmBase   = 2               // 1addrLen + 2port, plus addrLen
	lenHmacSha1 = 10
)

var debug ss.DebugLog
var udp bool

// 基于sock5协议
// host 目的地ip+port	ota是否加密
// 解析从local中来的数据，获取local中用户需要访问的真实服务器地址
func getRequest(conn *ss.Conn, auth bool) (host string, ota bool, err error) {
	ss.SetReadTimeout(conn) //超时设置

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 255(max length address) + 2(port) + 10(hmac-sha1)
	buf := make([]byte, 269)
	// read till we get possible domain length field
	if _, err = io.ReadFull(conn, buf[:idType+1]); err != nil {
		return
	}

	var reqStart, reqEnd int
	addrType := buf[idType]
	switch addrType & ss.AddrMask {
	case typeIPv4:
		reqStart, reqEnd = idIP0, idIP0+lenIPv4
	case typeIPv6:
		reqStart, reqEnd = idIP0, idIP0+lenIPv6
	case typeDm:
		if _, err = io.ReadFull(conn, buf[idType+1:idDmLen+1]); err != nil {
			return
		}
		reqStart, reqEnd = idDm0, idDm0+int(buf[idDmLen])+lenDmBase
	default:
		err = fmt.Errorf("addr type %d not supported", addrType&ss.AddrMask)
		return
	}

	if _, err = io.ReadFull(conn, buf[reqStart:reqEnd]); err != nil {
		return
	}

	// Return string for typeIP is not most efficient, but browsers (Chrome,
	// Safari, Firefox) all seems using typeDm exclusively. So this is not a
	// big problem.
	switch addrType & ss.AddrMask {
	case typeIPv4:
		host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		host = string(buf[idDm0 : idDm0+int(buf[idDmLen])])
	}
	// parse port
	port := binary.BigEndian.Uint16(buf[reqEnd-2 : reqEnd])
	host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	// if specified one time auth enabled, we should verify this
	if auth || addrType&ss.OneTimeAuthMask > 0 { //是否加密
		ota = true
		if _, err = io.ReadFull(conn, buf[reqEnd:reqEnd+lenHmacSha1]); err != nil {
			return
		}
		iv := conn.GetIv()
		key := conn.GetKey()
		actualHmacSha1Buf := ss.HmacSha1(append(iv, key...), buf[:reqEnd])
		if !bytes.Equal(buf[reqEnd:reqEnd+lenHmacSha1], actualHmacSha1Buf) {
			err = fmt.Errorf("verify one time auth failed, iv=%v key=%v data=%v", iv, key, buf[:reqEnd])
			return
		}
	}
	return
}

const logCntDelta = 100

var connCnt int
var nextLogConnCnt int = logCntDelta

//将local发送过来的用户数据，解析(若加密，则解密)后，发送给用户需要访问的真实服务器
//将用户访问的真实服务器返回的数据，返回给local,返回的数据没有加密啊，有被拦截的风险吧
func handleConnection(conn *ss.Conn, auth bool) {
	var host string

	//简单的记录链接数
	connCnt++ // this maybe not accurate, but should be enough
	if connCnt-nextLogConnCnt >= 0 {
		// XXX There's no xadd in the atomic package, so it's difficult to log
		// the message only once with low cost. Also note nextLogConnCnt maybe
		// added twice for current peak connection number level.
		log.Printf("Number of client connections reaches %d\n", nextLogConnCnt)
		nextLogConnCnt += logCntDelta
	}

	// function arguments are always evaluated, so surround debug statement
	// with if statement
	if debug {
		debug.Printf("new client %s->%s\n", conn.RemoteAddr().String(), conn.LocalAddr())
	}
	closed := false
	defer func() {
		if debug {
			debug.Printf("closed pipe %s<->%s\n", conn.RemoteAddr(), host)
		}
		connCnt--
		if !closed {
			conn.Close()
		}
	}()

	//解析协议，获取目的地ip地址，和加密情况
	host, ota, err := getRequest(conn, auth)
	if err != nil {
		log.Println("error getting request", conn.RemoteAddr(), conn.LocalAddr(), err)
		closed = true
		return
	}
	// ensure the host does not contain some illegal characters, NUL may panic on Win32
	if strings.ContainsRune(host, 0x00) {
		log.Println("invalid domain name.")
		closed = true
		return
	}
	debug.Println("connecting", host)
	remote, err := net.Dial("tcp", host) //链接服务器
	if err != nil {
		if ne, ok := err.(*net.OpError); ok && (ne.Err == syscall.EMFILE || ne.Err == syscall.ENFILE) {
			// log too many open file error
			// EMFILE is process reaches open file limits, ENFILE is system limit
			log.Println("dial error:", err)
		} else {
			log.Println("error connecting to:", host, err)
		}
		return
	}
	defer func() {
		if !closed {
			remote.Close()
		}
	}()
	if debug {
		debug.Printf("piping %s<->%s ota=%v connOta=%v", conn.RemoteAddr(), host, ota, conn.IsOta())
	}

	//从local过来的链接，读取数据，写数据到目标服务器
	if ota {
		go ss.PipeThenCloseOta(conn, remote) //从local过来的数据被加密，解析后，发送到目标服务器
	} else {
		go ss.PipeThenClose(conn, remote)
	}
	ss.PipeThenClose(remote, conn) //从目标服务器返回的数据，读取后，发送给local
	closed = true
	return
}

//tcp 密码和监听
type PortListener struct {
	password string
	listener net.Listener
}

//udp 密码和监听
type UDPListener struct {
	password string
	listener *net.UDPConn
}

//互斥锁，保存端口和密码/监听。可能更新密码操作，可能存在并发访问，加锁
type PasswdManager struct {
	sync.Mutex
	portListener map[string]*PortListener
	udpListener  map[string]*UDPListener
}

func (pm *PasswdManager) add(port, password string, listener net.Listener) {
	pm.Lock()
	pm.portListener[port] = &PortListener{password, listener}
	pm.Unlock()
}

func (pm *PasswdManager) addUDP(port, password string, listener *net.UDPConn) {
	pm.Lock()
	pm.udpListener[port] = &UDPListener{password, listener}
	pm.Unlock()
}

func (pm *PasswdManager) get(port string) (pl *PortListener, ok bool) {
	pm.Lock()
	pl, ok = pm.portListener[port]
	pm.Unlock()
	return
}

func (pm *PasswdManager) getUDP(port string) (pl *UDPListener, ok bool) {
	pm.Lock()
	pl, ok = pm.udpListener[port]
	pm.Unlock()
	return
}

//关闭监听，同时删除端口和监听数据
func (pm *PasswdManager) del(port string) {
	pl, ok := pm.get(port)
	if !ok {
		return
	}
	if udp {
		upl, ok := pm.getUDP(port)
		if !ok {
			return
		}
		upl.listener.Close()
	}
	pl.listener.Close()
	pm.Lock()
	delete(pm.portListener, port)
	if udp {
		delete(pm.udpListener, port)
	}
	pm.Unlock()
}

// Update port password would first close a port and restart listening on that
// port. A different approach would be directly change the password used by
// that port, but that requires **sharing** password between the port listener
// and password manager.
func (pm *PasswdManager) updatePortPasswd(port, password string, auth bool) {
	pl, ok := pm.get(port)
	if !ok { //监听不存在
		log.Printf("new port %s added\n", port)
	} else {
		if pl.password == password { //密码相同
			return
		}
		log.Printf("closing port %s to update password\n", port)
		pl.listener.Close() //密码不同，关闭监听
	}
	// run will add the new port listener to passwdManager.
	// So there maybe concurrent access to passwdManager and we need lock to protect it.
	go run(port, password, auth) //重新监听
	if udp {                     //udp，直接关闭监听，重新监听
		pl, _ := pm.getUDP(port)
		pl.listener.Close()
		go runUDP(port, password, auth)
	}
}

var passwdManager = PasswdManager{portListener: map[string]*PortListener{}, udpListener: map[string]*UDPListener{}}

func updatePasswd() {
	log.Println("updating password")
	newconfig, err := ss.ParseConfig(configFile)
	if err != nil {
		log.Printf("error parsing config file %s to update password: %v\n", configFile, err)
		return
	}
	oldconfig := config
	config = newconfig

	if err = unifyPortPassword(config); err != nil {
		return
	}
	for port, passwd := range config.PortPassword {
		passwdManager.updatePortPasswd(port, passwd, config.Auth)
		if oldconfig.PortPassword != nil {
			delete(oldconfig.PortPassword, port)
		}
	}
	// port password still left in the old config should be closed
	for port, _ := range oldconfig.PortPassword {
		log.Printf("closing port %s as it's deleted\n", port)
		passwdManager.del(port)
	}
	log.Println("password updated")
}

func waitSignal() {
	var sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	for sig := range sigChan {
		if sig == syscall.SIGHUP {
			updatePasswd()
		} else {
			// is this going to happen?
			log.Printf("caught signal %v, exit", sig)
			os.Exit(0)
		}
	}
}

func run(port, password string, auth bool) {
	ln, err := net.Listen("tcp", ":"+port) //监听tcp协议 所有ip地址 对port的链接
	if err != nil {
		log.Printf("error listening port %v: %v\n", port, err)
		os.Exit(1)
	}
	passwdManager.add(port, password, ln) //统一使用passwdManager管理所有的端口和监听
	var cipher *ss.Cipher                 //密码相关，在encrypt.go中
	log.Printf("server listening port %v ...\n", port)
	for {
		conn, err := ln.Accept() //等待链接
		if err != nil {
			// listener maybe closed to update password
			debug.Printf("accept error: %v\n", err)
			return
		}
		// Creating cipher upon first connection.
		if cipher == nil {
			log.Println("creating cipher for port:", port)
			cipher, err = ss.NewCipher(config.Method, password) //密码加密，方法在encrypt.go中
			if err != nil {
				log.Printf("Error generating cipher for port: %s %v\n", port, err)
				conn.Close()
				continue
			}
		}
		go handleConnection(ss.NewConn(conn, cipher.Copy()), auth) //每个协程，处理一次链接
	}
}

func runUDP(port, password string, auth bool) {
	var cipher *ss.Cipher
	port_i, _ := strconv.Atoi(port)
	log.Printf("listening udp port %v\n", port)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv6zero,
		Port: port_i,
	})
	passwdManager.addUDP(port, password, conn)
	if err != nil {
		log.Printf("error listening udp port %v: %v\n", port, err)
		return
	}
	defer conn.Close()
	cipher, err = ss.NewCipher(config.Method, password)
	if err != nil {
		log.Printf("Error generating cipher for udp port: %s %v\n", port, err)
		conn.Close()
	}
	SecurePacketConn := ss.NewSecurePacketConn(conn, cipher.Copy(), auth)
	for {
		if err := ss.ReadAndHandleUDPReq(SecurePacketConn); err != nil {
			debug.Println(err)
		}
	}
}

func enoughOptions(config *ss.Config) bool {
	return config.ServerPort != 0 && config.Password != ""
}

//检查端口和密码，以多端口多密码为准。单端口单密码，也保存到多端口多密码的map中
func unifyPortPassword(config *ss.Config) (err error) {
	if len(config.PortPassword) == 0 { // this handles both nil PortPassword and empty one
		if !enoughOptions(config) {
			fmt.Fprintln(os.Stderr, "must specify both port and password")
			return errors.New("not enough options")
		}
		port := strconv.Itoa(config.ServerPort)
		config.PortPassword = map[string]string{port: config.Password}
	} else {
		if config.Password != "" || config.ServerPort != 0 {
			fmt.Fprintln(os.Stderr, "given port_password, ignore server_port and password option")
		}
	}
	return
}

var configFile string
var config *ss.Config

func main() {
	log.SetOutput(os.Stdout) //日志输出目录

	var cmdConfig ss.Config
	var printVer bool
	var core int

	flag.BoolVar(&printVer, "version", false, "print version")                                                //打印版本
	flag.StringVar(&configFile, "c", "config.json", "specify config file")                                    //加载配置文件
	flag.StringVar(&cmdConfig.Password, "k", "", "password")                                                  //服务端密码
	flag.IntVar(&cmdConfig.ServerPort, "p", 0, "server port")                                                 //服务端端口
	flag.IntVar(&cmdConfig.Timeout, "t", 300, "timeout in seconds")                                           //超时时间
	flag.StringVar(&cmdConfig.Method, "m", "", "encryption method, default: aes-256-cfb")                     //加密方式
	flag.IntVar(&core, "core", 0, "maximum number of CPU cores to use, default is determinied by Go runtime") //cpu数目
	flag.BoolVar((*bool)(&debug), "d", false, "print debug message")                                          //debug模式
	flag.BoolVar(&udp, "u", false, "UDP Relay")                                                               //是否使用udp协议
	flag.Parse()

	//打印版本
	if printVer {
		ss.PrintVersion()
		os.Exit(0)
	}

	ss.SetDebug(debug) //debug模式

	//加密方法，后缀-auth的情况，代表需要加密
	if strings.HasSuffix(cmdConfig.Method, "-auth") {
		cmdConfig.Method = cmdConfig.Method[:len(cmdConfig.Method)-5]
		cmdConfig.Auth = true
	}

	var err error
	config, err = ss.ParseConfig(configFile) //若以配置文件的方式加载项目
	if err != nil {                          //文件不存在，以命令行参数为准
		if !os.IsNotExist(err) { //日志显示，读取文件错误
			fmt.Fprintf(os.Stderr, "error reading %s: %v\n", configFile, err)
			os.Exit(1)
		}
		config = &cmdConfig
		ss.UpdateConfig(config, config) //用后一个参数的配置覆盖前一个参数的配置
	} else {
		ss.UpdateConfig(config, &cmdConfig) //用后一个参数的配置覆盖前一个参数的配置，也就是命令行参数为准
	}

	if config.Method == "" { //默认，加密方法
		config.Method = "aes-256-cfb"
	}

	//检查用户限定的加密方式，是否在程序提供的加密范围内
	if err = ss.CheckCipherMethod(config.Method); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	//端口密码进行处理
	if err = unifyPortPassword(config); err != nil {
		os.Exit(1)
	}

	//用户级操作系统线程数
	if core > 0 {
		runtime.GOMAXPROCS(core)
	}

	//根据端口和密码信息，多协程
	for port, password := range config.PortPassword {
		go run(port, password, config.Auth)
		if udp {
			go runUDP(port, password, config.Auth)
		}
	}

	waitSignal()
}
