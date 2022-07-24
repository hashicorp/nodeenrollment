package net

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/protocol"
)

const (
	UnauthenticatedNextProto          = "__UNAUTH__"
	AuthenticatedNonSpecificNextProto = "__AUTH__"
)

type SplitConn struct {
	Conn net.Conn
	Err  error
}

// SplitListener can be useful for integration with systems that expect to do
// their own handling of connections off of a net.Listener. One such example is
// gRPC which expects to be handed a listener and has deprecated any ability to
// simply hand it a connection. GetListener can be called with
// AuthenticatedNonSpecificNextProto which in turn can be given to the gRPC
// server to pass authenticated connections to gRPC, and a listener with
// UnauthenticatedNextProto can be passed to another handler.
//
// SplitListener is compatible with the protocol package's Dialer's
// WithExtraAlpnProtos option. As the base listener is a *protocol.Listener, the
// client-specified NextProtos will be passed through to here and used to allow
// further switching based on listeners retrieved from GetListener with custom
// protos.
//
// Regardless of client-specified NextProto or not, any connection that's
// returned from a listener retrieved from GetListener will always have been
// authenticated with NodeEnrollment _unless_ they are coming from an
// UnauthenticatedNextProto listener.
//
// On receiving an error from the underlying Accept from the base listener that
// is not a Temporary error, the listener will stop listening.
type SplitListener struct {
	baseLn        *protocol.InterceptingListener
	babyListeners *sync.Map
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewSplitListener creates a new listener from a base listener, which must be a
// *protocol.InterceptingListener.
func NewSplitListener(baseLn net.Listener) (*SplitListener, error) {
	const op = "nodeenrollment.net.NewSplitListener"
	intLn, ok := baseLn.(*protocol.InterceptingListener)
	if !ok {
		return nil, fmt.Errorf("(%s): listener is not a *protocol.InterceptingListener", op)
	}

	l := &SplitListener{
		baseLn:        intLn,
		babyListeners: new(sync.Map),
	}
	l.ctx, l.cancel = context.WithCancel(context.Background())
	return l, nil
}

// Start starts the listener running. It will run until the base listener is
// closed, causing Accept to return a non-temporary error.
//
// Any temporary errors encountered will cause just that connection to be
// closed.
func (l *SplitListener) Start() error {
	defer func() {
		l.babyListeners.Range(func(k, v any) bool {
			v.(*monoplexingListener).Close()
			return true
		})
	}()
	for {
		conn, err := l.baseLn.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				l.cancel()
				return err
			}
			if tempErr, ok := err.(interface {
				Temporary() bool
			}); ok && tempErr.Temporary() {
				continue
			}
			l.cancel()
			return err
		}

		protoConn, ok := conn.(*protocol.Conn)
		if !ok {
			// It'd be nice not to be silent about this, but since we've
			// verified that only *protocol.InterceptingListener can be the
			// underlying listener, this should never really happen
			_ = conn.Close()
			continue
		}

		tlsConn := protoConn.Conn
		if !tlsConn.ConnectionState().HandshakeComplete {
			// Another case where assuming it is in fact the listener we expect,
			// it will always have performed a handshake as the protocol
			// requires it; so it'd be nice not to be silent about this, but
			// this should never really happen
			_ = conn.Close()
			continue
		}

		negProto := tlsConn.ConnectionState().NegotiatedProtocol
		if nodeenrollment.ContainsKnownAlpnProto(negProto) {
			if strings.HasPrefix(negProto, nodeenrollment.FetchNodeCredsNextProtoV1Prefix) {
				// If it's the fetch proto, the TLS handshake should be all that is
				// needed and the connection should be closed already. Close it for
				// safety and continue.
				_ = conn.Close()
				continue
			}

			// Get client conns and do a search
			clientNextProtos := protoConn.ClientNextProtos()
			var foundListener *monoplexingListener
			l.babyListeners.Range(func(k, v any) bool {
				for _, proto := range clientNextProtos {
					if k.(string) == proto {
						foundListener = v.(*monoplexingListener)
						return false
					}
				}
				return true
			})

			// If we didn't find something for that proto, look for a
			// non-specific authenticated listener
			if foundListener == nil {
				val, ok := l.babyListeners.Load(AuthenticatedNonSpecificNextProto)
				if ok {
					foundListener = val.(*monoplexingListener)
				}
			}

			// If we found a listener send the conn down, otherwise close the
			// conn
			if foundListener != nil {
				foundListener.incoming <- SplitConn{Conn: tlsConn}
			} else {
				_ = conn.Close()
			}
			continue
		}

		// Not authenticated
		val, ok := l.babyListeners.Load(UnauthenticatedNextProto)
		if !ok {
			_ = conn.Close()
		} else {
			val.(*monoplexingListener).incoming <- SplitConn{Conn: tlsConn}
		}
	}
}

// GetListener returns a listener that will return connections that satisfy both
// of the following:
//
// * It has been authenticated with the nodeenrollment library
//
// * The client handshake contained an ALPN NextProto value that has the given
// value (e.g. protocol.Dialer had the WithExtraAlpnProtos option specified)
//
// There are two special values:
//
// * If the given value is the AuthenticatedNonSpecificNextProto const value,
// any authenticated connection that does not match a specific value is returned
//
// * If the given value is the UnauthenticatedNextProto const value, any
// connection that is not authenticated by the nodeenrollment library will be
// returned on it. This includes connections that did not successfully TLS
// handshake or that are not TLS connections.
//
// The connections returned over the listener will always be *tls.Conn.
//
// If there was a previous listener for the given value, it is returned,
// otherwise a new one is created.
//
// Don't call GetListener after the underlying listener has been closed; this
// will result in an unclosed channel if there is a race.
func (l *SplitListener) GetListener(nextProto string) (net.Listener, error) {
	const op = "nodeenrollment.net.(SplitListener).GetListener"
	if nextProto == "" {
		return nil, fmt.Errorf("(%s): missing next proto value", op)
	}
	if l.ctx.Err() != nil {
		return nil, net.ErrClosed
	}

	newMonoplexingListener, err := NewMonoplexingListener(l.ctx, l.baseLn.Addr())
	if err != nil {
		return nil, fmt.Errorf("(%s): error creating monoplexing listener: %w", op, err)
	}

	existing, loaded := l.babyListeners.LoadOrStore(nextProto, newMonoplexingListener)
	if loaded {
		_ = newMonoplexingListener.Close()
		// In this case we know it's safe to close the channel too
		close(newMonoplexingListener.incoming)
		return existing.(*monoplexingListener), nil
	}
	return newMonoplexingListener, nil
}

type monoplexingListener struct {
	addr         net.Addr
	incoming     chan SplitConn
	ctx          context.Context
	cancel       context.CancelFunc
	drainSpawned *sync.Once
}

func NewMonoplexingListener(ctx context.Context, addr net.Addr) (*monoplexingListener, error) {
	const op = "nodeenrollment.net.NewMonoplexingListener"
	switch {
	case nodeenrollment.IsNil(ctx):
		return nil, fmt.Errorf("(%s): nil context", op)
	case nodeenrollment.IsNil(addr):
		return nil, fmt.Errorf("(%s): nil addr", op)
	}

	monoplexer := &monoplexingListener{
		addr:         addr,
		incoming:     make(chan SplitConn),
		drainSpawned: new(sync.Once),
	}
	monoplexer.ctx, monoplexer.cancel = context.WithCancel(ctx)

	return monoplexer, nil
}

// Addr satisfies the net.Listener interface and returns the base listener
// address
func (l *monoplexingListener) Addr() net.Addr {
	return l.addr
}

// Close satisfies the net.Listener interface and closes this specific listener.
// We call drainConnections here to ensure that senders don't block even though
// we're no longer accepting them.
func (l *monoplexingListener) Close() error {
	l.drainConnections()
	return nil
}

// Accept satisfies the net.Listener interface and returns the next connection
// that has been sent to this listener, or net.ErrClosed if the listener has
// been closed.
func (l *monoplexingListener) Accept() (net.Conn, error) {
	select {
	case <-l.ctx.Done():
		// If Close() was called this would happen anyways, but in case it
		// was only called on the parent context, ensure we drain
		// connections
		l.drainConnections()
		return nil, net.ErrClosed

	case in, ok := <-l.incoming:
		if !ok || nodeenrollment.IsNil(in.Conn) {
			// Channel has been closed
			return nil, net.ErrClosed
		}

		select {
		case <-l.ctx.Done():
			// Check one more time in case this was pseduo-randomly chosen as
			// the valid case and the context is done; if so close the conn and
			// return ErrClosed
			_ = in.Conn.Close()
			return nil, net.ErrClosed

		default:
			return in.Conn, in.Err
		}
	}
}

// IngressConns will read connections off the given listener until the listener
// is closed and returns net.ErrClosed; any other error during listen will be
// sent through as-is. Any conns will be put onto the internal channel. This
// function does not block; it will only ever error if the listener is nil.
func (l *monoplexingListener) IngressListener(ln net.Listener) error {
	const op = "nodeenrollment.net.(monoplexingListener).IngressConns"
	if ln == nil {
		return fmt.Errorf("%s: nil listener", op)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil && errors.Is(err, net.ErrClosed) {
				return
			}
			l.incoming <- SplitConn{Conn: conn, Err: err}
		}
	}()

	return nil
}

// drainConnections ensures we close any connections sent our way once the
// listener is closed so no open connections leak
func (l *monoplexingListener) drainConnections() {
	l.cancel()
	l.drainSpawned.Do(func() {
		go func() {
			for in := range l.incoming {
				if in.Conn != nil {
					_ = in.Conn.Close()
				}
			}
		}()
	})
}
