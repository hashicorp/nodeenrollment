package nodeauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/hashicorp/go-multierror"
	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/noderegistration"
	"github.com/hashicorp/nodeenrollment/nodetls"
	"github.com/hashicorp/nodeenrollment/nodetypes"
)

// tempError is an error that satisfies the temporary error interface that is
// internally used by gRPC to determine whether an error should cause a listener
// to die. Any error that isn't an accept error is wrapped in this since one
// connection failing TLS wise doesn't mean we don't want to accept any more...
type tempError struct {
	error
}

// NewTempError is a "temporary" error
func NewTempError(inner error) tempError {
	return tempError{error: inner}
}

func (t tempError) Temporary() bool {
	return true
}

// FetchCredsFn is a function that is used when a node requests fetching its
// initial credentials. It returns a response or an error. This is called during
// TLS negotiation for the given ALPN proto.
type FetchCredsFn = func(
	context.Context,
	nodee.Storage,
	*nodetypes.FetchNodeCredentialsRequest,
	...nodee.Option,
) (*nodetypes.FetchNodeCredentialsResponse, error)

// GenerateServerCertificatesFn is a function that is used when a node is connecting by
// the upstream node to fetch a certificate to present to the node. It returns a
// response or an error. This is called during TLS negotiation for the given
// ALPN proto.
type GenerateServerCertificatesFn = func(
	context.Context,
	nodee.Storage,
	*nodetypes.GenerateServerCertificatesRequest,
	...nodee.Option,
) (*nodetypes.GenerateServerCertificatesResponse, error)

// InterceptingListener is a listener that transparently handles fetch
// and auth flows if the right ALPN protos are found, and passes through
// otherwise
type InterceptingListener struct {
	baseLn                       net.Listener
	baseTlsConf                  *tls.Config
	factoryFn                    CurrentParameterFactory
	fetchCredsFn                 FetchCredsFn
	generateServerCertificatesFn GenerateServerCertificatesFn
}

// New creates a new listener based on the passed in listener (which should not
// be a TLS listener) and the given base TLS configuration. This function will
// substitute its own TLS configuration to handle the protos specific to nodee.
// Any connection coming in that is not using those protos will simply be passed
// through.
//
// The factoryFn parameter specifies a factory to provide, for each incoming
// connection, a context, _transactional_ storage, and a set of options (e.g. to
// include wrappers). Unlike functions in other parts of the library, the caller
// cannot simply know that when the top level function returns all storage is
// done, since this is called when connections come in, hence the transactional
// requirement.
//
// The fetchCredsFn parameter can be nil, in which case an internal function is
// used. This is appropriate for last-hop scenarios.
//
// The context value is not used here, but simply passed thorugh to other
// library functions. To stop the listener, close it normally.
func NewInterceptingListener(
	baseLn net.Listener,
	baseTlsConf *tls.Config,
	factoryFn CurrentParameterFactory,
	fetchCredsFn FetchCredsFn,
	generateServerCertificatesFn GenerateServerCertificatesFn,
) (*InterceptingListener, error) {
	const op = "nodee.nodeauth.NewInterceptingListener"
	l := &InterceptingListener{
		baseLn:                       baseLn,
		baseTlsConf:                  baseTlsConf,
		factoryFn:                    factoryFn,
		fetchCredsFn:                 fetchCredsFn,
		generateServerCertificatesFn: generateServerCertificatesFn,
	}
	switch {
	case baseLn == nil:
		return nil, fmt.Errorf("(%s) base listener is nil", op)
	case factoryFn == nil:
		return nil, fmt.Errorf("(%s) factory function is nil", op)
	}
	if l.fetchCredsFn == nil {
		l.fetchCredsFn = l.handleFetchCreds
	}
	if l.generateServerCertificatesFn == nil {
		l.generateServerCertificatesFn = nodetls.GenerateServerCertificates
	}
	return l, nil
}

func (l *InterceptingListener) getTlsConfigForClient(
	ctx context.Context,
	storage nodee.Storage,
	opt ...nodee.Option,
) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		// If they aren't announcing support, return the base configuration
		if !ContainsNodeAuthAlpnProto(hello.SupportedProtos...) {
			return l.baseTlsConf.GetConfigForClient(hello)
		}

		return NodeTlsConfig(ctx, storage, l.fetchCredsFn, l.generateServerCertificatesFn, opt...)(hello)
	}
}

func (l *InterceptingListener) Addr() net.Addr {
	return l.baseLn.Addr()
}

func (l *InterceptingListener) Close() error {
	return l.baseLn.Close()
}

// Accept accepts the next connection.
//
// If the TLS protos is one of our known credential fetching/auth protos, we'll
// handle it. Otherwise we pass through.
//
// You should check the resulting connection before trusting it. You can do that
// by seeing if the negotiated protocol was one handled by this library:
//
// if ContainsNodeAuthAlpnProto(
//     returnedConn.(*tls.Conn).ConnectionState().NegotiatedProtocol,
// ) {
//     // Authenticated by this library
// } else {
//     // Not authenticated by this library
// }
//
// There is also some special behavior around the errors that this function
// returns. For compatibility with listeners passed into gRPC servers, most
// errors satisfy a Temporary interface so that returning an error does not
// cause the gRPC server to shut down the listener, which should really only
// happen for system-level errors rather than connection-specific errors. For
// gRPC this should likely just work, but if you need to check if this is a true
// error in your own code, you can do this:
//
//  if tempErr, ok := err.(interface {
//    Temporary() bool
//  }); ok && tempErr.Temporary() {
//
// If it's temporary, continue on and accept the next connection.
//
// Finally, in some cases the connection's lifecycle is fully served within this
// function, so returning a conn that is non-nil but closed would lead to
// errors, and returning a nil connection but also nil error would lead to
// panics (such as in gRPC). As a result, there is a special error (which is
// also a Temporary error) indicating that the connection was full served:
// ErrConnFullyServed. This can be used with errors.Is to perform any needed
// special handling.
func (l *InterceptingListener) Accept() (conn net.Conn, retErr error) {
	const op = "nodee.nodeauth.(InterceptingListener).Accept"
	for {
		conn, err := l.baseLn.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil, net.ErrClosed
			}
			return nil, fmt.Errorf("(%s) error accepting connection: %w", op, err)
		}
		if conn == nil {
			continue
		}

		ctx, storage, opt, err := l.factoryFn()
		if err != nil {
			return nil, fmt.Errorf("(%s) factory func returned error", op)
		}
		if storage == nil {
			return nil, fmt.Errorf("(%s) factory func returned nil storage", op)
		}

		success := new(bool)
		defer func() {
			if err := storage.Flush(*success); err != nil {
				retErr = multierror.Append(retErr, err)
			}
		}()

		tlsConn := tls.Server(conn, &tls.Config{
			GetConfigForClient: l.getTlsConfigForClient(
				ctx,
				storage,
				opt...),
		})

		if err := tlsConn.HandshakeContext(ctx); err != nil {
			// log.Println("error handshaking", err)
			if closeErr := tlsConn.Close(); closeErr != nil {
				err = multierror.Append(err, fmt.Errorf("(%s) error closing connection: %w", op, closeErr))
			}
			return nil, NewTempError(fmt.Errorf("(%s) error tls handshaking connection: %w", op, err))
		}

		// Now that we've performed the handshake, see if it's one of our known
		// protos. If so invoke our function.
		negProto := tlsConn.ConnectionState().NegotiatedProtocol
		switch {
		case strings.HasPrefix(negProto, nodee.FetchNodeCredsNextProtoV1Prefix):
			// If we got here we've already sent back the creds, so return a
			// temp error so we keep the listener alive
			*success = true
			return nil, NewTempError(errors.New("fetch handled, awaiting auth connection"))

		default:
			*success = true
			return tlsConn, nil
		}
	}
}

// handleFetchCreds handles the protos supported for credential fetching
func (l *InterceptingListener) handleFetchCreds(
	ctx context.Context,
	storage nodee.Storage,
	req *nodetypes.FetchNodeCredentialsRequest,
	opt ...nodee.Option,
) (*nodetypes.FetchNodeCredentialsResponse, error) {
	const op = "nodee.nodeauth.(InterceptingListener).handleFetchCreds"

	// Attempt the fetch
	resp, err := noderegistration.FetchNodeCredentials(
		ctx,
		storage,
		req,
		opt...,
	)
	if err != nil {
		return nil, fmt.Errorf("(%s) error fetching node credentials: %w", op, err)
	}
	return resp, nil
}
