package poplib

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
)

const (
	// DefaultPort means POP3 uses port 110 by default.
	DefaultPort = 110

	// DefaultPortSSL means POP3 uses port 995 when connected vis SSL.
	DefaultPortSSL = 995

	defaultTimeout = 1
	netProtocol    = "tcp"
	bufSiz         = uint(4096)

	CommandQuit = "QUIT"
)

// Line terminators (we always output CRLF, but accept any of CRLF, LF)
var (
	logger = log.StandardLogger()

	// POP protocol response prefix.
	prefixOk = []byte("+OK")
)

// Client is implemented POP3 client, according to RFC 1939.
type Client struct {
	Host     string
	Port     uint
	UseTLS   bool
	KeyFile  string
	CertFile string
	Timeout  uint

	fd        net.Conn
	mutex     sync.Mutex
	certs     *x509.CertPool
	tlsConfig *tls.Config
}

// Addr joins host and port returns joined string.
func (c Client) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// NewClient initializes a new client instance.
func NewClient(host string, port uint, timeout uint) (*Client, error) {
	if 0 == port || "" == host {
		return nil, errors.New("bad host or port")
	}

	if 0 == timeout {
		timeout = defaultTimeout
	}

	client := &Client{
		Host:     host,
		Port:     port,
		UseTLS:   false,
		KeyFile:  "",
		CertFile: "",
		Timeout:  timeout,

		fd:        nil,
		certs:     nil,
		tlsConfig: nil,
	}

	return client, nil
}

// NewClientSSL initializes a new client instance with SSL/TLS configuration.
func NewClientSSL(host string, port uint, timeout uint, keyFile, certFile string) (*Client, error) {
	var err error

	cli, err := NewClient(host, port, timeout)
	if nil != err {
		return nil, err
	}

	cli.UseTLS = true
	cli.CertFile = certFile
	cli.KeyFile = keyFile

	// Note:
	// - Only AEAD ciphers allowed.
	// - DES/3DES/RC4 are not allowed.
	// - SSL and TLS version lower than 1.1 are not enabled.
	// - TLS 1.3 enabled.
	cli.tlsConfig = &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,

			// TLS 1.3 Ciphers.
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},

		MaxVersion: tls.VersionTLS13,
		MinVersion: tls.VersionTLS11,
	}

	err = cli.loadCerts()
	if nil != err {
		return nil, err
	}

	if nil != cli.certs {
		cli.tlsConfig.RootCAs = cli.certs
	}

	return cli, nil
}

func (c *Client) loadCerts() error {
	if "" == c.CertFile {
		return nil
	}

	pem, err := ioutil.ReadFile(c.CertFile)
	if nil != err {
		return err
	}

	if nil == c.certs {
		c.certs = x509.NewCertPool()
	}

	c.certs.AppendCertsFromPEM(pem)
	return nil
}

func (c *Client) Connect() error {
	var err error = nil

	c.mutex.Lock()
	if c.UseTLS {
		err = c.connectTLS()
		c.mutex.Unlock()
		return err
	}

	err = c.connect()
	c.mutex.Unlock()
	return err
}

func (c *Client) connect() error {
	conn, err := net.Dial(netProtocol, c.Addr())
	if nil != err {
		return err
	}

	c.fd = conn
	return nil
}

func (c *Client) connectTLS() error {
	conn, err := tls.Dial(netProtocol, c.Addr(), c.tlsConfig)
	if nil != err {
		return err
	}

	c.fd = conn
	return nil
}

func (c *Client) GetWelcome() ([]byte, error) {
	c.mutex.Lock()
	line, err := c.readFirstLine()
	if nil != err {
		c.mutex.Unlock()
		return nil, err
	}

	c.mutex.Unlock()
	logger.Debug(string(line))
	return line, nil
}

func (c *Client) Close() error {
	c.mutex.Lock()
	if nil == c.fd {
		c.mutex.Unlock()
		return nil
	}

	_, _ = c.writeCmd(FormatCommand(CommandQuit))

	err := c.fd.Close()
	c.fd = nil

	c.mutex.Unlock()
	return err
}

func (c *Client) readFirstLine() ([]byte, error) {
	reader := bufio.NewReader(c.fd)
	line, _, err := reader.ReadLine()
	if nil != err {
		return nil, err
	}

	if bytes.HasPrefix(line, prefixOk) {
		return line, nil
	}

	return nil, errors.New(string(line))
}

func (c *Client) readBody() ([]byte, error) {
	//reader := bufio.NewReader(c.fd)

	return nil, nil
}

// WriteCmd writes POP3 command to server, and
// reads single line or long response.
func (c *Client) WriteCmd(cmd []byte, singleLine bool) ([]byte, error) {
	var (
		err error = nil
	)

	c.mutex.Lock()
	if nil == c.fd {
		c.mutex.Unlock()
		return nil, errors.New("not connected or connection closed")
	}

	r, err := c.writeCmd(cmd)
	if nil != err {
		c.mutex.Unlock()
		return nil, err
	}

	if singleLine {
		c.mutex.Unlock()
		return r, nil
	}

	body, err := c.readBody()
	if nil != err {
		c.mutex.Unlock()
		return nil, err
	}

	// Join first line with its body.
	if nil != body {
		r = append(r, body...)
	}

	c.mutex.Unlock()
	return r, err
}

// writeCmd is the REAL executor without lock.
// he writes command, and reads the first line of
// response.
func (c *Client) writeCmd(cmd []byte) ([]byte, error) {
	_, err := c.fd.Write(cmd)
	if nil != err {
		return nil, nil
	}

	line, err := c.readFirstLine()
	if nil != err {
		return nil, err
	}

	return line, nil
}
