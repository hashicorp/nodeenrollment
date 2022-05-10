package nodeauth

import (
	"crypto/tls"
	"errors"
	"net"

	"go.uber.org/atomic"
)

type teeConn struct {
	conn net.Conn
	err  error
}

type TeeListener struct {
	baseLn                     net.Listener
	nodeeBabyTee, otherBabyTee *babyTeeListener
	stopped                    *atomic.Bool
}

func NewTeeListener(baseLn net.Listener) *TeeListener {
	tl := &TeeListener{
		baseLn:  baseLn,
		stopped: atomic.NewBool(false),
	}
	tl.nodeeBabyTee = &babyTeeListener{
		tl:       tl,
		incoming: make(chan teeConn),
	}
	tl.otherBabyTee = &babyTeeListener{
		tl:       tl,
		incoming: make(chan teeConn),
	}
	return tl
}

func (l *TeeListener) Stop() error {
	if l.stopped.CAS(false, true) {
		close(l.nodeeBabyTee.incoming)
		close(l.otherBabyTee.incoming)
		return l.baseLn.Close()
	}
	return nil
}

func (l *TeeListener) Start() error {
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
			l.otherBabyTee.incoming <- teeConn{err: NewTempError(errors.New("expected tls connection but it is not"))}
			continue
		}
		if !tlsConn.ConnectionState().HandshakeComplete {
			l.otherBabyTee.incoming <- teeConn{err: NewTempError(errors.New("tls handshake is not complete"))}
			continue
		}

		switch ContainsNodeAuthAlpnProto(tlsConn.ConnectionState().NegotiatedProtocol) {
		case true:
			l.nodeeBabyTee.incoming <- teeConn{conn: tlsConn}
		default:
			l.otherBabyTee.incoming <- teeConn{conn: tlsConn}
		}
	}
}

func (l *TeeListener) NodeeListener() net.Listener {
	return l.nodeeBabyTee
}

func (l *TeeListener) OtherListener() net.Listener {
	return l.otherBabyTee
}

type babyTeeListener struct {
	tl       *TeeListener
	incoming chan teeConn
}

func (l *babyTeeListener) Addr() net.Addr {
	return l.tl.baseLn.Addr()
}

// Close is here to satisfy the listener interface. Close the TeeListener, not
// this.
func (l *babyTeeListener) Close() error {
	return nil
}

func (l *babyTeeListener) Accept() (net.Conn, error) {
	for in := range l.incoming {
		return in.conn, in.err
	}
	return nil, net.ErrClosed
}
