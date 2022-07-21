package net

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/protocol"
	"github.com/hashicorp/nodeenrollment/util/temperror"
	"go.uber.org/atomic"
)

type splitConn struct {
	conn net.Conn
	err  error
}

// SplitListener takes in a base listener and sends incoming connections to one
// of two listeners: one that is used if the TLS connection negotiated to one of
// this package's standard ALPN proto values and one if not.
//
// It is required that the base listener return *tls.Conn values on Accept.
//
// This package can be useful for integration with systems that expect to do
// their own handling of connections off of a net.Listener. One such example is
// gRPC which expects to be handed a listener and has deprecated any ability to
// simply hand it a connection. The NodeEnrollmentListener can be given to the
// gRPC server and the OtherListener can be used for other purposes.
//
// On receiving an error from the underlying Accept from the base listener that
// is not a Temporary error, the listener will stop listening.
//
// NOTE: The NodeEnrollmentListener will return values of type *protocol.Conn;
// the OtherListener will return values of type *tls.Conn.
type SplitListener struct {
	baseLn                               net.Listener
	nodeeBabyListener, otherBabyListener *babySplitListener
	stopped                              *atomic.Bool
}

// NewSplitListener creates a new listener from a base. The base listener must
// return *tls.Conn connections (or a net.Conn that is type-assertable to
// *tls.Conn).
func NewSplitListener(baseLn net.Listener) *SplitListener {
	tl := &SplitListener{
		baseLn:  baseLn,
		stopped: atomic.NewBool(false),
	}
	tl.nodeeBabyListener = &babySplitListener{
		tl:           tl,
		incoming:     make(chan splitConn),
		drainSpawned: new(sync.Once),
	}
	tl.nodeeBabyListener.ctx, tl.nodeeBabyListener.cancel = context.WithCancel(context.Background())
	tl.otherBabyListener = &babySplitListener{
		tl:           tl,
		incoming:     make(chan splitConn),
		drainSpawned: new(sync.Once),
	}
	tl.otherBabyListener.ctx, tl.otherBabyListener.cancel = context.WithCancel(context.Background())
	return tl
}

// Start starts the listener running. It will run until the base listener is
// closed, causing Accept to return a non-temporary error.
//
// Any temporary errors encountered will cause just that connection to be
// closed.
func (l *SplitListener) Start() error {
	defer func() {
		close(l.nodeeBabyListener.incoming)
		close(l.otherBabyListener.incoming)
	}()
	for {
		if l.stopped.Load() {
			return net.ErrClosed
		}
		conn, err := l.baseLn.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			if tempErr, ok := err.(interface {
				Temporary() bool
			}); ok && tempErr.Temporary() {
				continue
			}
			return err
		}

		var tlsConn *tls.Conn
		switch c := conn.(type) {
		case *protocol.Conn:
			tlsConn = c.Conn
		case *tls.Conn:
			tlsConn = c
		default:
			_ = conn.Close()
			l.otherBabyListener.incoming <- splitConn{err: temperror.New(fmt.Errorf("unknown connection type %T", c))}
			continue
		}

		if !tlsConn.ConnectionState().HandshakeComplete {
			if err := tlsConn.Handshake(); err != nil {
				// Without a successful handshake we can't know which proto;
				// send down the other listener
				_ = tlsConn.Close()
				l.otherBabyListener.incoming <- splitConn{err: temperror.New(fmt.Errorf("tls handshake resulted in error: %w", err))}
				continue
			}
		}

		negProto := tlsConn.ConnectionState().NegotiatedProtocol
		switch nodeenrollment.ContainsKnownAlpnProto(negProto) {
		case true:

			if strings.HasPrefix(negProto, nodeenrollment.AuthenticateNodeNextProtoV1Prefix) {
				// This is the only case when we actually send the connection
				// over -- when it's been fully authenticated
				l.nodeeBabyListener.incoming <- splitConn{conn: conn}
			} else {
				// If it's the fetch proto, the TLS handshake should be all that is
				// needed and the connection should be closed already. Close it for
				// safety.
				_ = conn.Close()
			}
		default:
			l.otherBabyListener.incoming <- splitConn{conn: tlsConn}
		}
	}
}

// NodeEnrollmentListener returns the listener receiving connections related to
// this library
func (l *SplitListener) NodeEnrollmentListener() net.Listener {
	return l.nodeeBabyListener
}

// OtherListener returns the listener receving all other connections
func (l *SplitListener) OtherListener() net.Listener {
	return l.otherBabyListener
}

type babySplitListener struct {
	tl           *SplitListener
	incoming     chan splitConn
	ctx          context.Context
	cancel       context.CancelFunc
	drainSpawned *sync.Once
}

// Addr satisfies the net.Listener interface and returns the base listener
// address
func (l *babySplitListener) Addr() net.Addr {
	return l.tl.baseLn.Addr()
}

// Close satisfies the net.Listener interface and closes this specific listener.
// We call drainConnections here in case Accept hasn't been called.
func (l *babySplitListener) Close() error {
	l.cancel()
	l.drainConnections()
	return nil
}

// Accept satisfies the net.Listener interface and returns any connections that
// have been sent to this listener. Accept will return when the channel is shut
// down, which happens when Stop is called on the SplitListener (or the
// underlying listener is closed), which also closes the underlying listener,
// hence once the range ends we return net.ErrClosed.
func (l *babySplitListener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.ctx.Done():
			// If Close() was called this would happen anyways, but in case it
			// was only called on the parent listener, ensure we drain
			// connections
			l.drainConnections()
			return nil, net.ErrClosed

		case in, ok := <-l.incoming:
			if !ok {
				// Channel has been closed, trigger cancel behavior and loop
				// back up to the case above
				l.cancel()
				continue
			}
			select {
			case <-l.ctx.Done():
				// Check one more time in case this was pseduo-randomly chosen
				// as the valid case
				return nil, net.ErrClosed
			default:
				return in.conn, in.err
			}
		}
	}
}

// drainConnections ensures we close any connections sent our way once the
// listener is closed so no open connections leak
func (l *babySplitListener) drainConnections() {
	l.drainSpawned.Do(func() {
		go func() {
			for in := range l.incoming {
				if in.conn != nil {
					_ = in.conn.Close()
				}
			}
		}()
	})
}
