package protocol

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	nodetls "github.com/hashicorp/nodeenrollment/tls"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/hashicorp/nodeenrollment/util/temperror"
)

// InterceptingListener is a listener that transparently handles fetch
// and auth flows if the right ALPN protos are found, and passes through
// otherwise
type InterceptingListener struct {
	ctx                          context.Context
	storage                      nodeenrollment.Storage
	baseLn                       net.Listener
	baseTlsConf                  *tls.Config
	fetchCredsFn                 FetchCredsFn
	generateServerCertificatesFn GenerateServerCertificatesFn
	options                      []nodeenrollment.Option
}

// InterceptingListenerConfiguration contains config information for
// InterceptingListener
type InterceptingListenerConfiguration struct {
	// The context that will be used to call any functions once a connection is
	// accepted. Required.
	Context context.Context

	// The storage that will be used for any storage needs for connections.
	// Required.
	Storage nodeenrollment.Storage

	// The base listener to accept connections from and possibly intercept.
	// Required.
	BaseListener net.Listener

	// The TLS configuration to use if the incoming connection is not one
	// handled by this library. If nil, any connection not handled by this
	// library will be closed.
	BaseTlsConfiguration *tls.Config

	// The function to use for the FetchCredentials operation. If nil, the
	// default will be used, which is suitable for a server.
	FetchCredsFunc FetchCredsFn

	// The function to use for the GenerateServerCertificates operation. If nil,
	// the default will be used, which is suitable for a server.
	GenerateServerCertificatesFunc GenerateServerCertificatesFn

	// If provided, options to pass into various storage functions, e.g.
	// WithRandomReader and WithWrapper
	Options []nodeenrollment.Option
}

// New creates a new listener based on the passed in listener (which should not
// be a TLS listener) and the given base TLS configuration. This function will
// substitute its own TLS configuration to handle the protos specific to
// nodeenrollment. Any connection coming in that is not using those protos will
// simply be passed through.
//
// The context value is not used here, but simply passed through to other
// library functions. To stop the listener, close it normally.
func NewInterceptingListener(
	config *InterceptingListenerConfiguration,
) (*InterceptingListener, error) {
	const op = "nodeenrollment.protocol.NewInterceptingListener"

	switch {
	case config == nil:
		return nil, fmt.Errorf("(%s) configuration is nil", op)
	case nodeenrollment.IsNil(config.Context):
		return nil, fmt.Errorf("(%s) context is nil", op)
	case nodeenrollment.IsNil(config.Storage):
		return nil, fmt.Errorf("(%s) storage is nil", op)
	case nodeenrollment.IsNil(config.BaseListener):
		return nil, fmt.Errorf("(%s) base listener is nil", op)
	case config.BaseTlsConfiguration == nil:
		return nil, fmt.Errorf("(%s) base tls configuration is nil", op)
	}

	l := &InterceptingListener{
		ctx:                          config.Context,
		storage:                      config.Storage,
		baseLn:                       config.BaseListener,
		baseTlsConf:                  config.BaseTlsConfiguration,
		fetchCredsFn:                 config.FetchCredsFunc,
		generateServerCertificatesFn: config.GenerateServerCertificatesFunc,
		options:                      config.Options,
	}

	if l.fetchCredsFn == nil {
		l.fetchCredsFn = func(
			ctx context.Context,
			storage nodeenrollment.Storage,
			req *types.FetchNodeCredentialsRequest,
			opt ...nodeenrollment.Option,
		) (*types.FetchNodeCredentialsResponse, error) {
			return registration.FetchNodeCredentials(ctx, storage, req, opt...)
		}
	}
	if l.generateServerCertificatesFn == nil {
		l.generateServerCertificatesFn = func(
			ctx context.Context,
			storage nodeenrollment.Storage,
			req *types.GenerateServerCertificatesRequest,
			opt ...nodeenrollment.Option,
		) (*types.GenerateServerCertificatesResponse, error) {
			return nodetls.GenerateServerCertificates(ctx, storage, req, opt...)
		}
	}

	return l, nil
}

// Accept accepts the next connection.
//
// If the TLS protos is one of our known credential fetching/auth protos, we'll
// handle it. Otherwise we pass through.
//
// You should check the resulting connection before trusting it. You can do that
// by seeing if the negotiated protocol was the auth protocol handled by this
// library:
//
// if strings.HasPrefix(
//      returnedConn.(*tls.Conn).ConnectionState().NegotiatedProtocol,
//      nodeenrollment.AuthenticateNodeNextProtoV1Prefix
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
func (l *InterceptingListener) Accept() (conn net.Conn, retErr error) {
	const op = "nodeenrollment.protocol.(InterceptingListener).Accept"
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

		// Wrap the connection in our config
		tlsConn := tls.Server(conn, &tls.Config{
			GetConfigForClient: l.getTlsConfigForClient,
		})

		// Force a handshake to run our logic
		if err := tlsConn.HandshakeContext(l.ctx); err != nil {
			// If there is an error close the connection
			if closeErr := tlsConn.Close(); closeErr != nil {
				err = multierror.Append(err, fmt.Errorf("error closing connection: %w", closeErr))
			}
			// Return a temp error so we don't close the listener
			return nil, temperror.New(fmt.Errorf("(%s) error tls handshaking connection: %w", op, err))
		}

		// Now that we've performed the handshake, see if it's a fetch. If so,
		// we want to close the connection and return a temp error either way so
		// that the node either retries with new creds or tries again to fetch later.
		if strings.HasPrefix(tlsConn.ConnectionState().NegotiatedProtocol, nodeenrollment.FetchNodeCredsNextProtoV1Prefix) {
			err := fmt.Errorf("(%s) fetch handled, awaiting auth connection", op)
			// If we got here we've already sent back the creds, so close the
			// connection and return a temp error so we keep the listener alive
			if closeErr := tlsConn.Close(); closeErr != nil {
				err = multierror.Append(err, fmt.Errorf("error closing connection: %w", closeErr))
			}
			return nil, temperror.New(err)
		}

		return tlsConn, nil
	}
}

// Addr satisfies the net.Listener interface and simply returns the base
// listener's address
func (l *InterceptingListener) Addr() net.Addr {
	return l.baseLn.Addr()
}

// Close satisfies the net.Listener interface and closes the base listener
func (l *InterceptingListener) Close() error {
	return l.baseLn.Close()
}
