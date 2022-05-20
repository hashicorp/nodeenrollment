package splitlistener

import (
	"crypto/tls"
	"errors"
	"net"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/util/temperror"
	"go.uber.org/atomic"
)

type splitConn struct {
	conn net.Conn
	err  error
}

// SplitListener takes in a base listener and sends incoming connections to one
// of two listeners: one that is used if the TLS connection negoatiated to one
// of this package's standard ALPN proto values and one if not.
//
// It is required that the base listener return *tls.Conn values on Accept.
//
// This package can be useful for integration with systems that expect to do
// their own handling of connections off of a net.Listener. One such example is
// gRPC which expects to be handed a listener and has deprecated any abiliy to
// simply hand it a connection. The NodeEnrollmentListener can be given to the
// gRPC server and the OtherListener can be used for other purposes.
//
// On receiving an error from the underlying Accept from the base listener that
// is not a Temporary error, the listener will stop listening.
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
		tl:       tl,
		incoming: make(chan splitConn),
	}
	tl.otherBabyListener = &babySplitListener{
		tl:       tl,
		incoming: make(chan splitConn),
	}
	return tl
}

// Stop stops the listener. If this is the first time it's called it will close
// the baby listeners' incoming channel (causing them to terminate) and will
// close the underlying base listener, returning that error. On any future call
// it is a noop.
func (l *SplitListener) Stop() error {
	if l.stopped.CAS(false, true) {
		close(l.nodeeBabyListener.incoming)
		close(l.otherBabyListener.incoming)
		return l.baseLn.Close()
	}
	return nil
}

// Start starts the listener running. It will run until Stop is called, causing
// the base listener to Close and the Accept to return a non-temporary error.
//
// Any temporary errors encountered will
func (l *SplitListener) Start() error {
	for {
		conn, err := l.baseLn.Accept()
		if err != nil {
			if tempErr, ok := err.(interface {
				Temporary() bool
			}); ok && tempErr.Temporary() {
				continue
			}
			return err
		}
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			// This is an error; put it out the other listener but as a temp
			// error so we accept more
			l.otherBabyListener.incoming <- splitConn{err: temperror.New(errors.New("expected tls connection but it is not"))}
			continue
		}
		if !tlsConn.ConnectionState().HandshakeComplete {
			// By the time we get this the handshake should be complete; if not
			// we don't know what protocol was negotiated and can't proceed.
			l.otherBabyListener.incoming <- splitConn{err: temperror.New(errors.New("tls handshake is not complete"))}
			continue
		}

		switch nodeenrollment.ContainsKnownAlpnProto(tlsConn.ConnectionState().NegotiatedProtocol) {
		case true:
			l.nodeeBabyListener.incoming <- splitConn{conn: tlsConn}
		default:
			l.otherBabyListener.incoming <- splitConn{conn: tlsConn}
		}
	}
}

// NodeEnrollmentListner returns the listener receiving connections related to
// this library
func (l *SplitListener) NodeEnrollmentListener() net.Listener {
	return l.nodeeBabyListener
}

// OtherListener returns the listener receving all other connections
func (l *SplitListener) OtherListener() net.Listener {
	return l.otherBabyListener
}

type babySplitListener struct {
	tl       *SplitListener
	incoming chan splitConn
}

// Addr satisfies the net.Listener interface and returns the base listener
// address
func (l *babySplitListener) Addr() net.Addr {
	return l.tl.baseLn.Addr()
}

// Close satisfies the net.Listener interface. It does nothing; close the
// SplitListener, not this.
func (l *babySplitListener) Close() error {
	return nil
}

// Accept satisfies the net.Listener interface and returns any connections that
// have been sent to this listener. Accept will return when the channel is shut
// down, which happens when Stop is called on the SplitListener, which also
// closes the underlying listner, hence once the range ends we return
// net.ErrClosed.
func (l *babySplitListener) Accept() (net.Conn, error) {
	for in := range l.incoming {
		return in.conn, in.err
	}
	return nil, net.ErrClosed
}
