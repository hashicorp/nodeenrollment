// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/nodeenrollment"
	"google.golang.org/protobuf/types/known/structpb"
)

var errNilConn = errors.New("nil conn")

// Conn wraps a *tls.Conn and allows us to add protocol-specific state around
// handshake completion and client metadata.
type Conn struct {
	*tls.Conn
	handshakeFn      func(*Conn) error
	handshakeOnce    sync.Once
	handshakeDone    chan struct{}
	handshakeErr     error
	clientNextProtos []string
	clientState      *structpb.Struct
}

// newConn supports an optional tls handshake function that can be used to define the handshake behavior.
// All methods that require the handshake to be complete before working (e.g. Read, Write, ConnectionState) will
// block until the handshake is complete.
// If handshakeFn is nil, it is assumed that the handshake is already complete and will not block.
func newConn(base *tls.Conn, handshakeFn func(*Conn) error, opt ...nodeenrollment.Option) (*Conn, error) {
	const op = "nodeenrollment.protocol.newConn"
	if base == nil {
		return nil, fmt.Errorf("(%s) nil base conn", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	conn := &Conn{
		Conn:          base,
		handshakeFn:   handshakeFn,
		handshakeDone: make(chan struct{}),
		clientState:   opts.WithState,
	}
	switch {
	case opts.WithExtraAlpnProtos == nil:
	case len(opts.WithExtraAlpnProtos) == 0:
		conn.clientNextProtos = make([]string, 0)
	default:
		conn.clientNextProtos = make([]string, len(opts.WithExtraAlpnProtos))
		copy(conn.clientNextProtos, opts.WithExtraAlpnProtos)
	}

	if handshakeFn == nil {
		close(conn.handshakeDone)
	}

	return conn, nil
}

// NewConn constructs a conn from a base TLS connection and possibly client next
// protos.
//
// Supported options: WithExtraAlpnProtos (used to set clientNextProtos),
// WithState (storing client state information)
func NewConn(base *tls.Conn, opt ...nodeenrollment.Option) (*Conn, error) {
	return newConn(base, nil, opt...)
}

// startHandshake starts the handshake process in a separate goroutine. This is safe
// to call multiple times, and will only execute the handshakeFn once.
func (c *Conn) startHandshake() {
	if c == nil {
		return
	}

	c.handshakeOnce.Do(func() {
		if c.handshakeFn == nil {
			return
		}

		go func() {
			defer close(c.handshakeDone)
			c.handshakeErr = c.handshakeFn(c)
		}()
	})
}

// waitForHandshake waits for the handshake to complete and returns any error that
// occurred during the handshake. If the handshake has not been started, it will start it first.
func (c *Conn) waitForHandshake() error {
	if c == nil || c.handshakeDone == nil {
		return errNilConn
	}

	c.startHandshake()
	<-c.handshakeDone
	return c.handshakeErr
}

func (c *Conn) setClientInfo(nextProtos []string, state *structpb.Struct) {
	if c == nil {
		return
	}

	c.clientNextProtos = append([]string(nil), nextProtos...)
	c.clientState = state
}

// Read reads data from the connection.
// If a handshakeFn was provided, it waits for the handshake to complete.
func (c *Conn) Read(b []byte) (int, error) {
	if c == nil || c.Conn == nil {
		return 0, errNilConn
	}

	if err := c.waitForHandshake(); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

// Write writes data to the connection.
// If a handshakeFn was provided, it waits for the handshake to complete.
func (c *Conn) Write(b []byte) (int, error) {
	if c == nil || c.Conn == nil {
		return 0, errNilConn
	}

	if err := c.waitForHandshake(); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// Handshake begins the TlsHandshake if a handshakeFn was provided, and blocks until the handshake is complete.
// If no handshakeFn was provided, this is a no-op.
func (c *Conn) Handshake() error {
	return c.waitForHandshake()
}

// HandshakeContext begins the TlsHandshake if a handshakeFn was provided, and blocks until the handshake is complete
// or the provided context is done.
// If no handshakeFn was provided, this is a no-op.
func (c *Conn) HandshakeContext(ctx context.Context) error {
	if c == nil || c.handshakeDone == nil {
		return errNilConn
	}

	c.startHandshake()
	select {
	case <-c.handshakeDone:
		return c.handshakeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ConnectionState returns basic TLS details about the connection.
// If a handshakeFn was provided, it waits for the handshake to complete.
func (c *Conn) ConnectionState() tls.ConnectionState {
	if c == nil || c.Conn == nil {
		return tls.ConnectionState{}
	}

	_ = c.waitForHandshake()
	return c.Conn.ConnectionState()
}

// ClientNextProtos returns the value of NextProtos originally presented by the
// client at connection time
func (c *Conn) ClientNextProtos() []string {
	if c == nil {
		return nil
	}

	_ = c.waitForHandshake()

	switch {
	case c.clientNextProtos == nil:
		return nil
	case len(c.clientNextProtos) == 0:
		return []string{}
	default:
		ret := make([]string, len(c.clientNextProtos))
		copy(ret, c.clientNextProtos)
		return ret
	}
}

// ClientState returns the value of the state embedded into the original client
// request, which may be nil.
// If a handshakeFn was provided, it waits for the handshake to complete.
func (c *Conn) ClientState() *structpb.Struct {
	if c == nil {
		return nil
	}

	_ = c.waitForHandshake()

	return c.clientState
}
