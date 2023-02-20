package shadowtls

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"net"
	"os"

	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type ClientConfig struct {
	Version      int
	Password     string
	Server       M.Socksaddr
	Dialer       N.Dialer
	TLSHandshake TLSHandshakeFunc
}

type Client struct {
	version      int
	password     string
	server       M.Socksaddr
	dialer       N.Dialer
	tlsHandshake TLSHandshakeFunc
}

func NewClient(config ClientConfig) (*Client, error) {
	client := &Client{
		version:      config.Version,
		password:     config.Password,
		server:       config.Server,
		dialer:       config.Dialer,
		tlsHandshake: config.TLSHandshake,
	}
	if !client.server.IsValid() || client.dialer == nil || client.tlsHandshake == nil {
		return nil, os.ErrInvalid
	}
	switch client.version {
	case 1, 2:
	case 3:
	default:
		return nil, E.New("unknown protocol version: ", client.version)
	}
	if client.dialer == nil {
		client.dialer = N.SystemDialer
	}
	return client, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialer.DialContext(ctx, N.NetworkTCP, c.server)
	if err != nil {
		return nil, err
	}
	switch c.version {
	default:
		fallthrough
	case 1:
		err = c.tlsHandshake(ctx, conn, nil)
		if err != nil {
			return nil, err
		}
		return conn, nil
	case 2:
		hashConn := newHashReadConn(conn, c.password)
		err = c.tlsHandshake(ctx, conn, nil)
		if err != nil {
			return nil, err
		}
		return newClientConn(hashConn), nil
	case 3:
		stream := newStreamWrapper(conn, c.password)
		err = c.tlsHandshake(ctx, stream, generateSessionID(c.password))
		if err != nil {
			return nil, err
		}
		authorized, serverRandom, readHMAC := stream.Authorized()
		if !authorized {
			return nil, E.New("traffic hijacked or TLS1.3 is not supported")
		}
		hmacAdd := hmac.New(sha1.New, []byte(c.password))
		hmacAdd.Write(serverRandom)
		hmacAdd.Write([]byte("C"))
		hmacVerify := hmac.New(sha1.New, []byte(c.password))
		hmacVerify.Write(serverRandom)
		hmacVerify.Write([]byte("S"))
		return newVerifiedConn(conn, hmacAdd, hmacVerify, readHMAC), nil
	}
}
