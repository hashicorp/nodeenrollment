package protocol

import "crypto/tls"

// Conn embeds a *tls.Conn and allows us to add extra bits into it
type Conn struct {
	*tls.Conn
	clientNextProtos []string
}

// NewConn constructs a conn from a base TLS connection and possibly client next
// protos
func NewConn(base *tls.Conn, clientNextProtos []string) *Conn {
	conn := &Conn{Conn: base}
	switch {
	case clientNextProtos == nil:
	case len(clientNextProtos) == 0:
		conn.clientNextProtos = make([]string, 0)
	default:
		conn.clientNextProtos = make([]string, len(clientNextProtos))
		copy(conn.clientNextProtos, clientNextProtos)
	}
	return conn
}

// ClientNextProtos returns the value of NextProtos originally presented by the
// client at connection time
func (c *Conn) ClientNextProtos() []string {
	switch {
	case c == nil:
		return nil
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
