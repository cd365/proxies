package proxies

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	VersionSocks   = byte(0x05) // socks5协议版本号
	NegotiationVer = byte(0x01) // RFC-1929 sub-negotiation version 账号密码认证
)

const (
	Auth00 = byte(0x00) // 不需要认证(常用)
	Auth01 = byte(0x01) // GSSAPI认证
	Auth02 = byte(0x02) // 账号密码认证(常用)
	Auth03 = byte(0x03) // 0x03-0x7F IANA分配
	Auth80 = byte(0x80) // 0x80-0xFE 私有方法保留
	AuthFF = byte(0xFF) // 无支持的认证方法
)

const (
	Auth0000 = byte(0x00) // 不需要认证(常用)
	Auth0200 = byte(0x00) // 用户密码认证成功
	Auth0201 = byte(0x01) // 用户密码认证失败(大于0x00)
)

const (
	Cmd01 = byte(0x01) // CONNECT 连接上游服务器
	Cmd02 = byte(0x02) // BIND 绑定,客户端会接收来自代理服务器的链接,著名的FTP被动模式
	Cmd03 = byte(0x03) // UDP ASSOCIATE UDP中继
)

const (
	Rsv00 = byte(0x00) // 保留位 值是0x00
)

const (
	Rep00 = byte(0x00) // 0x00 代理服务器连接目标服务器成功
	Rep01 = byte(0x00) // 0x01 代理服务器故障
	Rep02 = byte(0x00) // 0x02 代理服务器规则集不允许连接
	Rep03 = byte(0x00) // 0x03 网络无法访问
	Rep04 = byte(0x00) // 0x04 目标服务器无法访问(主机名无效)
	Rep05 = byte(0x00) // 0x05 连接目标服务器被拒绝
	Rep06 = byte(0x00) // 0x06 TTL已过期
	Rep07 = byte(0x00) // 0x07 不支持的命令
	Rep08 = byte(0x00) // 0x08 不支持的目标服务器地址类型
	// 0x09 - 0xFF 未分配
)

const (
	AddressType01 = byte(0x01) // IPV4地址
	AddressType03 = byte(0x03) // 域名地址,域名地址的第1个字节为域名长度,剩下字节为域名名称字节数组
	AddressType04 = byte(0x04) // IPV6地址
)

type Conn struct {
	conn net.Conn
}

func (s *Conn) Read(b []byte) (n int, err error) {
	return s.conn.Read(b)
}

func (s *Conn) Write(b []byte) (n int, err error) {
	return s.conn.Write(b)
}

func (s *Conn) Close() error {
	return s.conn.Close()
}

type Proxy struct {
	// listenAddress Server listen address.
	listenAddress string

	// listenPort Server listen port.
	listenPort int

	// ProxyAddress Proxy address.
	ProxyAddress *string
}

func NewProxy() *Proxy {
	return &Proxy{}
}

func (s *Proxy) Listen(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()

	s.listenAddress = address
	index := strings.LastIndex(s.listenAddress, ":")
	s.listenPort, err = strconv.Atoi(s.listenAddress[index+1:])
	if err != nil {
		return err
	}

	for {
		conn, rer := listener.Accept()
		if rer != nil {
			continue
		}
		go s.handle(&Conn{conn: conn})
	}
}

func (s *Proxy) handle(conn *Conn) {
	defer conn.Close()

	if s.ProxyAddress != nil {
		dialer := &net.Dialer{
			Timeout: time.Second * 30,
		}
		proxyConn, err := dialer.Dial("tcp", *s.ProxyAddress)
		if err != nil {
			return
		}
		defer proxyConn.Close()
		go io.Copy(proxyConn, conn)
		io.Copy(conn, proxyConn)
		return
	}

	// 读取客户端发送的认证数据包
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+

	firstByte := make([]byte, 1)
	n, err := conn.Read(firstByte)
	if err != nil || n == 0 {
		return
	}
	if firstByte[0] != VersionSocks {
		s.TryHttp(conn, firstByte[0], fmt.Sprintf("localhost:%d", s.listenPort))
		return
	}

	count := make([]byte, 1)
	n, err = conn.Read(count)
	if err != nil || n == 0 {
		return
	}
	methods := make([]byte, int(count[0]))
	n, err = conn.Read(methods)
	if err != nil || n == 0 {
		return
	}

	// 选择认证方式并认证连接
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	// 如果存在多个认证方法,服务器可以任意选择一个受支持的方法进行认证
	// 这里默认选择第一个方法
	switch methods[0] {
	case Auth00: // 不需要认证
		_, err = conn.Write([]byte{VersionSocks, Auth00})
		if err != nil {
			return
		}
	case Auth02: // 账号密码认证
		_, err = conn.Write([]byte{VersionSocks, Auth02})
		if err != nil {
			return
		}
		// 从客户端读取认证数据,认证数据之后立即响应认证结果

		// 读取认证数据
		// +----+------+----------+------+----------+
		// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		// +----+------+----------+------+----------+
		// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		// +----+------+----------+------+----------+
		ver := make([]byte, 1)
		n, err = conn.Read(ver)
		if err != nil || n == 0 {
			return
		}
		if ver[0] != NegotiationVer {
			return
		}
		usernameLength := make([]byte, 1)
		n, err = conn.Read(usernameLength)
		if err != nil || n == 0 {
			return
		}
		username := make([]byte, int(usernameLength[0]))
		n, err = conn.Read(username)
		if err != nil || n == 0 {
			return
		}
		passwordLength := make([]byte, 1)
		n, err = conn.Read(passwordLength)
		if err != nil || n == 0 {
			return
		}
		password := make([]byte, int(passwordLength[0]))
		n, err = conn.Read(password)
		if err != nil || n == 0 {
			return
		}
		// 响应认证结果
		// +----+--------+
		// |VER | STATUS |
		// +----+--------+
		// | 1  |   1    |
		// +----+--------+
		// 账号或密码错误
		if string(username) == "" || string(password) == "" {
			n, err = conn.Write([]byte{NegotiationVer, Auth0201})
			if err != nil || n == 0 {
				return
			}
			return
		}
		// 账号和密码正确
		n, err = conn.Write([]byte{NegotiationVer, Auth0200})
		if err != nil || n == 0 {
			return
		}
	default: // 其它认证,暂不支持
		return
	}

	// 读取请求数据
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	ver := make([]byte, 1)
	n, err = conn.Read(ver)
	if err != nil || n == 0 || ver[0] != VersionSocks {
		return
	}
	cmd := make([]byte, 1)
	n, err = conn.Read(cmd)
	if err != nil || n == 0 {
		return
	}
	rsv := make([]byte, 1)
	n, err = conn.Read(rsv)
	if err != nil || n == 0 || rsv[0] != Rsv00 {
		return
	}

	var dstAddrBytes []byte
	var dstAddr net.IP
	var dstPort uint16
	// read dst addr, dst port
	addressType := make([]byte, 1)
	n, err = conn.Read(addressType)
	if err != nil || n == 0 {
		return
	}
	// read address
	switch addressType[0] {
	case AddressType01:
		dstAddrBytes = make([]byte, 4)
		n, err = conn.Read(dstAddrBytes)
		if err != nil || n < 4 {
			return
		}
		dstAddr = dstAddrBytes
	case AddressType03:
		addrLength := make([]byte, 1)
		n, err = conn.Read(addrLength)
		if err != nil || n == 0 {
			return
		}
		dstAddrBytes = make([]byte, int(addrLength[0]))
		n, err = conn.Read(dstAddrBytes)
		if err != nil || n == 0 {
			return
		}
		tmp, rer := net.ResolveIPAddr("ip", string(dstAddrBytes))
		if rer != nil {
			return
		}
		dstAddr = tmp.IP
	case AddressType04:
		dstAddrBytes = make([]byte, 16)
		n, err = conn.Read(dstAddrBytes)
		if err != nil || n < 16 {
			return
		}
		dstAddr = dstAddrBytes
	default:
		return
	}
	// read port
	port := make([]byte, 2)
	n, err = conn.Read(port)
	if err != nil || n != 2 {
		return
	}
	dstPort = uint16(port[0])<<8 + uint16(port[1])

	// 根据不同的命令分别处理请求数据
	switch cmd[0] {
	case Cmd01:
		tcpAddr := &net.TCPAddr{
			IP:   dstAddr,
			Port: int(dstPort),
		}
		dstConn, der := net.DialTCP("tcp", nil, tcpAddr)
		if der != nil {
			return
		}
		defer dstConn.Close()

		// 响应连接上游服务器的请求
		// +----+-----+-------+------+----------+----------+
		// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		// +----+-----+-------+------+----------+----------+
		// | 1  |  1  | X'00' |  1   | Variable |    2     |
		// +----+-----+-------+------+----------+----------+

		// 返回当前主机的ip和端口
		local := dstConn.LocalAddr().(*net.TCPAddr)
		localIp := local.IP
		localPort := local.Port
		{
			resp := []byte{VersionSocks, Rep00, Rsv00}
			if localIp.To4() != nil {
				// v4
				resp = append(resp, AddressType01)
				resp = append(resp, localIp.To4()...)
			} else {
				// v6
				resp = append(resp, AddressType04)
				resp = append(resp, localIp.To16()...)
			}
			port1 := byte((localPort & 0xff00) >> 8)
			port2 := byte(localPort & 0xff)
			resp = append(resp, port1, port2)
			if _, err = conn.Write(resp); err != nil {
				return
			}
		}

		go io.Copy(dstConn, conn)
		io.Copy(conn, dstConn)

		// now proxy done.

	default: // 其它命令暂不支持
		return
	}
}

var (
	ErrUnsupportedProtocol = errors.New("unsupported protocol")
)

// NewSocks5Conn 创建socks5代理连接
func (s *Proxy) NewSocks5Conn(proxyAddress string, targetHost string, targetPort int) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxyAddress)
	if err != nil {
		return nil, err
	}
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	_, err = conn.Write([]byte{VersionSocks, byte(0x01), Auth00})
	if err != nil {
		return nil, err
	}
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	authResult := make([]byte, 2)
	_, err = conn.Read(authResult)
	if err != nil {
		return nil, err
	}
	if authResult[0] != VersionSocks {
		return nil, ErrUnsupportedProtocol
	}
	if authResult[1] != Auth0000 {
		return nil, errors.New("auth fail")
	}
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	req := []byte{VersionSocks, Cmd01, Rsv00}
	ip := net.ParseIP(targetHost)
	if ip != nil {
		ipv4 := ip.To4()
		if ipv4 != nil {
			req = append(req, AddressType01)
			req = append(req, ipv4...)
		} else {
			req = append(req, AddressType04)
			req = append(req, ip.To16()...)
		}
	} else {
		length := len(targetHost)
		if length == 0 || length > 255 {
			return nil, errors.New("dst.addr is invalid")
		}
		req = append(req, AddressType03)
		req = append(req, byte(length))
		req = append(req, targetHost...)
	}
	port1 := byte((targetPort & 0xff00) >> 8)
	port2 := byte(targetPort & 0xff)
	req = append(req, port1, port2)
	if _, err = conn.Write(req); err != nil {
		return nil, err
	}

	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	resp := make([]byte, 4)
	if _, err = conn.Read(resp); err != nil {
		return nil, err
	}
	if resp[0] != VersionSocks || resp[1] != Rep00 || resp[2] != Rsv00 {
		return nil, ErrUnsupportedProtocol
	}
	switch resp[3] {
	case AddressType01:
		ip1 := make([]byte, 4)
		if _, err = conn.Read(ip1); err != nil {
			return nil, err
		}
	case AddressType04:
		ip1 := make([]byte, 16)
		if _, err = conn.Read(ip1); err != nil {
			return nil, err
		}
	default:
		return nil, ErrUnsupportedProtocol
	}
	port := make([]byte, 2)
	if _, err = conn.Read(port); err != nil {
		return nil, err
	}
	return conn, nil
}

// TryHttp 尝试处理http或https请求
func (s *Proxy) TryHttp(conn *Conn, read byte, proxyAddress string) {
	reader := bufio.NewReader(conn)
	req := make([]byte, 1, 512)
	req[0] = read
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			return
		}
		// each line of the http message is divided using 0x0d 0x0a \r\n
		line = append(line, 0x0d, 0x0a)
		req = append(req, line...)
		if len(line) == 2 && line[0] == 0x0d && line[1] == 0x0a {
			break
		}
	}

	request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(req)))
	if err != nil {
		return
	}
	bodyLength := request.ContentLength
	if bodyLength != 0 {
		// get http request body
		body := make([]byte, bodyLength)
		if _, err = conn.Read(body); err != nil {
			return
		}
		req = append(req, body...)
	}

	targetHost := request.Host
	targetPort := 80
	last := strings.LastIndex(request.Host, ":")
	if last == -1 {
		if request.Method == http.MethodConnect {
			targetPort = 443
		}
	} else {
		targetHost = request.Host[:last]
		if tmpPort, ter := strconv.Atoi(request.Host[last+1:]); ter == nil {
			targetPort = tmpPort
		}
	}

	proxyConn, err := s.NewSocks5Conn(proxyAddress, targetHost, targetPort)
	if err != nil {
		return
	}
	defer proxyConn.Close()

	// method is CONNECT for https
	if request.Method == http.MethodConnect {
		_, err = conn.Write([]byte("HTTP/1.0 200\r\n\r\n"))
		if err != nil {
			return
		}
	} else {
		// request
		_, err = proxyConn.Write(req)
		if err != nil {
			return
		}
	}
	go io.Copy(conn, proxyConn)
	io.Copy(proxyConn, conn)
}
