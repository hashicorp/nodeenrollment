package protocol

import "crypto/tls"

// Conn embeds a *tls.Conn and allows us to add extra bits into it
type Conn struct {
	*tls.Conn
	clientNextProtos []string
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
