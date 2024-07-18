package proxies

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	localListenAddress string

	username string
	password string

	remoteListenAddress string
	secret              string
}

func NewClient(
	localListenAddress string,
	username string,
	password string,
	remoteListenAddress string,
	secret string,
) *Client {
	return &Client{
		localListenAddress:  localListenAddress,
		username:            username,
		password:            password,
		remoteListenAddress: remoteListenAddress,
		secret:              secret,
	}
}

func (s *Client) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.localListenAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	ok := true
	go func() {
		<-ctx.Done()
		ok = false
	}()
	fmt.Println("server started on:", s.localListenAddress)
	for ok {
		conn, rer := listener.Accept()
		if rer != nil {
			continue
		}
		go s.handle(NewConn(conn))
	}
	return nil
}

// NewProxyConn 创建代理连接
func (s *Client) NewProxyConn(proxyAddress string, targetHost string, targetPort int) (*Conn, error) {
	dialer := &net.Dialer{
		Timeout: time.Second * 5,
	}
	if proxyAddress == "" {
		proxyConn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", targetHost, targetPort))
		if err != nil {
			return nil, err
		}
		conn := NewConn(proxyConn)
		return conn, nil
	}
	proxyConn, err := dialer.Dial("tcp", proxyAddress)
	if err != nil {
		return nil, err
	}

	conn := NewConn(proxyConn)

	auth, err := AuthEncrypt([]byte(s.secret))
	if err != nil {
		return nil, err
	}
	auth = append(auth, '\n')
	_, err = conn.Write(auth)
	if err != nil {
		return nil, err
	}

	target := fmt.Sprintf("%s:%d", targetHost, targetPort)
	address, err := AuthEncrypt([]byte(target))
	if err != nil {
		return nil, err
	}
	address = append(address, '\n')
	if _, err = conn.Write(address); err != nil {
		return nil, err
	}
	return conn, nil
}

// TryHttp 尝试处理http或https请求
func (s *Client) TryHttp(conn *Conn, read byte) {
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

	remote, err := s.NewProxyConn(s.remoteListenAddress, targetHost, targetPort)
	if err != nil {
		return
	}
	defer remote.Close()

	// method is CONNECT for https
	if request.Method == http.MethodConnect {
		_, err = conn.Write([]byte("HTTP/1.0 200\r\n\r\n"))
		if err != nil {
			return
		}
	} else {
		// request
		_, err = remote.Write(req)
		if err != nil {
			return
		}
	}
	go io.Copy(conn, remote)
	io.Copy(remote, conn)
}

func (s *Client) handle(conn *Conn) {
	defer conn.Close()

	// 读取客户端发送的认证数据包
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+

	first := make([]byte, 1)
	n, err := conn.Read(first)
	if err != nil || n == 0 {
		return
	}
	if first[0] != VersionSocks {
		if s.username == "" && s.password == "" {
			s.TryHttp(conn, first[0])
		}
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
		if s.username != "" && s.password != "" {
			n, err = conn.Write([]byte{NegotiationVer, Auth0201})
			if err != nil || n == 0 {
				return
			}
			return
		}
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
		if string(username) != s.username || string(password) != s.password {
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
		dstConn, der := s.NewProxyConn(s.remoteListenAddress, dstAddr.String(), int(dstPort))
		if der != nil {
			return
		}
		defer dstConn.Close()

		// 响应客户端连接的请求
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

		go io.Copy(conn, dstConn)
		io.Copy(dstConn, conn)

		// now proxy done.

	default: // 其它命令暂不支持
	}
}
