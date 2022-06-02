package protocol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/nodeenrollment"
	nodetls "github.com/hashicorp/nodeenrollment/tls"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/proto"
)

// Dial returns a function suitable for dialing a connection to an
// InterceptingListener. It takes in storage, an address, and options.
//
// Supported options: WithRandomReader, WithWrapper (passed through to
// LoadNodeCredentials and NodeCredentials.Store)
func Dial(
	ctx context.Context,
	storage nodeenrollment.Storage,
	addr string,
	opt ...nodeenrollment.Option,
) (net.Conn, error) {
	const op = "nodeenrollment.protocol.Dial"

	switch {
	case nodeenrollment.IsNil(ctx):
		return nil, fmt.Errorf("(%s) nil context", op)
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) nil storage", op)
	}

	nonTlsConnFn := func() (net.Conn, error) {
		dialer := &net.Dialer{}
		var err error
		var nonTlsConn net.Conn
		switch {
		case strings.HasPrefix(addr, "/"):
			nonTlsConn, err = dialer.DialContext(ctx, "unix", addr)
		default:
			nonTlsConn, err = dialer.DialContext(ctx, "tcp", addr)
		}
		if err != nil {
			return nil, fmt.Errorf("(%s) unable to dial to server: %w", op, err)
		}
		return nonTlsConn, nil
	}

	creds, err := types.LoadNodeCredentials(ctx, storage, nodeenrollment.CurrentId, opt...)
	if err != nil && !errors.Is(err, nodeenrollment.ErrNotFound) {
		return nil, fmt.Errorf("(%s) unable to load node credentials: %w", op, err)
	}
	if creds == nil {
		return nil, fmt.Errorf("(%s) loaded node credentials are nil", op)
	}

	if len(creds.CertificateBundles) == 0 {
		// We haven't fetched creds yet, so attempt it
		nonTlsConn, err := nonTlsConnFn()
		if err != nil {
			return nil, fmt.Errorf("(%s) unable to dial to server: %w", op, err)
		}

		fetchResp, err := attemptFetch(ctx, nonTlsConn, creds, opt...)
		closeErr := nonTlsConn.Close()
		if closeErr != nil {
			err = multierror.Append(err, fmt.Errorf("(%s) error closing initial connection: %w", op, closeErr))
		}
		if err != nil {
			return nil, err
		}

		if !fetchResp.Authorized {
			return nil, fmt.Errorf("(%s) not yet authorized", op)
		}

		if err := creds.HandleFetchNodeCredentialsResponse(ctx, storage, fetchResp, opt...); err != nil {
			return nil, fmt.Errorf("(%s) error handling fetch creds response from server: %w", op, err)
		}

		// At this point if there is no error we have found and saved our
		// creds, and can proceed connecting
	}

	nonTlsConn, err := nonTlsConnFn()
	if err != nil {
		return nil, fmt.Errorf("(%s) unable to dial to controller: %w", op, err)
	}

	tlsConfig, err := nodetls.ClientConfig(ctx, creds, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) unable to get tls config from node creds: %w", op, err)
	}
	tlsConn := tls.Client(nonTlsConn, tlsConfig)

	return tlsConn, nil
}

// attemptFetch creates a signed fetch request and tries to perform a TLS
// handshake, reading the resulting certificate
func attemptFetch(ctx context.Context, nonTlsConn net.Conn, creds *types.NodeCredentials, opt ...nodeenrollment.Option) (*types.FetchNodeCredentialsResponse, error) {
	const op = "nodeenrollment.protocol.attemptFetch"

	switch {
	case creds == nil:
		return nil, fmt.Errorf("(%s) nil creds", op)
	case creds.CertificatePrivateKeyPkcs8 == nil:
		return nil, fmt.Errorf("(%s) nil certificate private key", op)
	case creds.CertificatePublicKeyPkix == nil:
		return nil, fmt.Errorf("(%s) nil certificate public key", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	req, err := creds.CreateFetchNodeCredentialsRequest(ctx, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error creating fetch request: %w", op, err)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(creds.CertificatePrivateKeyPkcs8)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing private key: %w", op, err)
	}
	pubKey, err := x509.ParsePKIXPublicKey(creds.CertificatePublicKeyPkix)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing public key: %w", op, err)
	}

	reqMsg, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("(%s) error marshaling request message: %w", op, err)
	}
	reqMsgString := base64.RawStdEncoding.EncodeToString(reqMsg)

	splitNextProtos, err := nodetls.BreakIntoNextProtos(nodeenrollment.FetchNodeCredsNextProtoV1Prefix, reqMsgString)
	if err != nil {
		return nil, fmt.Errorf("(%s) error splitting request into next protos: %w", op, err)
	}

	// We need to use TLS for the connection but we aren't relying on its
	// security. Create a self-signed cert and embed our info into it.
	template := &x509.Certificate{
		AuthorityKeyId: creds.CertificatePublicKeyPkix,
		SubjectKeyId:   creds.CertificatePublicKeyPkix,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:              []string{nodeenrollment.CommonDnsName},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotBefore:             time.Now().Add(nodeenrollment.NotBeforeDuration),
		NotAfter:              time.Now().Add(-1 * nodeenrollment.NotBeforeDuration),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(opts.WithRandomReader, template, template, pubKey, privKey)
	if err != nil {
		return nil, fmt.Errorf("(%s) error creating certificate: %w", op, err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{
			certBytes,
		},
		PrivateKey: privKey,
	}

	tlsConf := &tls.Config{
		Rand: opts.WithRandomReader,
		GetClientCertificate: func(
			cri *tls.CertificateRequestInfo,
		) (*tls.Certificate, error) {
			return tlsCert, nil
		},
		MinVersion: tls.VersionTLS13,
		// We are using TLS as transport for signed, public information or
		// encrypted information only; we do not rely on it for security
		InsecureSkipVerify: true,
		NextProtos:         splitNextProtos,
	}

	tlsConn := tls.Client(nonTlsConn, tlsConf)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("(%s) error tls handshaking connection: %w", op, err)
	}

	respBytes, err := base64.RawStdEncoding.DecodeString(tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName)
	if err != nil {
		return nil, fmt.Errorf("(%s) error base64 decoding fetch response: %w", op, err)
	}
	fetchResp := new(types.FetchNodeCredentialsResponse)
	if err := proto.Unmarshal(respBytes, fetchResp); err != nil {
		return nil, fmt.Errorf("(%s) error decoding response from server: %w", op, err)
	}

	return fetchResp, nil
}
