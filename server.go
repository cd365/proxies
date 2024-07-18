package proxies

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

type Server struct {
	localListenAddress string

	secret string
}

func NewServer(
	localListenAddress string,
	secret string,
) *Server {
	return &Server{
		localListenAddress: localListenAddress,
		secret:             secret,
	}
}

func (s *Server) Start(ctx context.Context) error {
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

func (s *Server) handle(conn *Conn) {
	defer conn.Close()

	// 读取客户端发送的认证数据包
	reader := bufio.NewReader(conn)
	first, _, err := reader.ReadLine()
	if err != nil {
		return
	}
	secret, err := AuthDecrypt(first)
	if err != nil {
		return
	}
	if string(secret) != s.secret {
		return
	}

	address, _, err := reader.ReadLine()
	if err != nil {
		return
	}
	dstAddress, err := AuthDecrypt(address)
	if err != nil {
		return
	}

	dialer := &net.Dialer{
		Timeout: time.Second * 5,
	}
	dstConn, der := dialer.Dial("tcp", string(dstAddress))
	if der != nil {
		return
	}
	defer dstConn.Close()

	go io.Copy(conn, dstConn)
	io.Copy(dstConn, conn)

}
