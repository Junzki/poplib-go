package poplib

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
)

const (
	DefaultPort    = 110
	DefaultTimeout = 1
	netProtocol    = "tcp"
)

type Client struct {
	Host     string
	Port     uint
	UseTLS   bool
	KeyFile  string
	CertFile string
	Timeout  uint

	fd        net.Conn
	certs     *x509.CertPool
	tlsConfig *tls.Config
}

func (c Client) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

func NewClient(host string, port uint, timeout uint) (*Client, error) {
	if 0 == port || "" == host {
		return nil, errors.New("bad host or port")
	}

	if 0 == timeout {
		timeout = DefaultTimeout
	}

	client := &Client{
		Host:     host,
		Port:     port,
		UseTLS:   false,
		KeyFile:  "",
		CertFile: "",
		Timeout:  DefaultTimeout,

		fd:        nil,
		certs:     nil,
		tlsConfig: nil,
	}

	return client, nil
}

func NewClientTLS(host string, port uint, timeout uint, keyFile, certFile string) (*Client, error) {
	var err error = nil

	cli, err := NewClient(host, port, timeout)
	if nil != err {
		return nil, err
	}

	cli.UseTLS = true
	cli.CertFile = certFile
	cli.KeyFile = keyFile
	cli.tlsConfig = &tls.Config{
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		},
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
	if c.UseTLS {
		return c.connectTLS()
	}

	return c.connect()
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
	return nil
}

func (c *Client) Close() error {
	if nil == c.fd {
		return nil
	}

	err := c.fd.Close()
	c.fd = nil

	return err
}

func (c *Client) WriteCmd(cmd []byte) ([]byte, error) {
	if nil != c.fd {
		return nil, errors.New("not connected or connection closed")
	}

	return nil, nil
}

func (c *Client) Auth(user, password string) error {
	return nil
}
