package proxies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"net"
)

type Conn struct {
	conn net.Conn
}

func NewConn(conn net.Conn) *Conn {
	return &Conn{
		conn: conn,
	}
}

func (s *Conn) Read(b []byte) (int, error) {
	return s.conn.Read(b)
}

func (s *Conn) Write(b []byte) (int, error) {
	return s.conn.Write(b)
}

func (s *Conn) Close() error {
	return s.conn.Close()
}

func (s *Conn) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *Conn) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

var (
	AuthKey string
	gcm     cipher.AEAD
)

func init() {
	key := []byte(AuthKey)
	length := len(key)
	if length != 32 {
		key = []byte("61BD60C60D9FB60CC8FC7767669E30A1")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err = cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
}

func AuthEncrypt(plaintext []byte) ([]byte, error) {
	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)
	encryptedData := iv[:]
	encryptedData = append(encryptedData, ciphertext...)
	return encryptedData, nil
}

func AuthDecrypt(encryptedData []byte) ([]byte, error) {
	length := len(encryptedData)
	if length < 12 {
		return nil, errors.New("error data")
	}
	iv, ciphertext := encryptedData[:12], encryptedData[12:]
	return gcm.Open(nil, iv, ciphertext, nil)
}
