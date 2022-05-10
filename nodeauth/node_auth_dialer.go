package nodeauth

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
	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/nodetls"
	"github.com/hashicorp/nodeenrollment/nodetypes"
	"google.golang.org/protobuf/proto"
)

// AuthDialFn returns a function suitable for dialing a connection to a
// NodeAuthInterceptingListener. It takes in storage; a function to return the
// current credentials (which may be nil, if we need to fetch them, which this
// function will perform); a function to return the current id (which may change
// if we rotate keys); and options for wrappers.
//
// Supported options: WithRandomReader, WithWrapper (passed thorugh to NodeCredentials.Store)
func AuthDialFn(
	factoryFn CurrentParameterFactory,
) func(context.Context, string) (net.Conn, error) {
	const op = "nodee.nodeauth.AuthDialFn"
	return func(ctx context.Context, addr string) (retConn net.Conn, retErr error) {
		if factoryFn == nil {
			return nil, fmt.Errorf("(%s) factory func is nil", op)
		}
		// We'll use the context passed in here, so ignore the first parameter
		_, storage, opt, err := factoryFn()
		if err != nil {
			return nil, fmt.Errorf("(%s) factory func returned error", op)
		}
		if storage == nil {
			return nil, fmt.Errorf("(%s) factory func returned nil storage", op)
		}

		defer func() {
			if err := storage.Flush(retErr == nil); err != nil {
				retErr = multierror.Append(retErr, err)
			}
		}()

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

		creds, err := nodetypes.LoadNodeCredentials(ctx, storage, nodee.CurrentId, opt...)
		if err != nil && !errors.Is(err, nodee.ErrNotFound) {
			return nil, fmt.Errorf("(%s) unable to load node credentials: %w", op, err)
		}
		if creds == nil {
			return nil, fmt.Errorf("(%s) loaded node credentils are nil", op)
		}

		if len(creds.CertificateBundles) == 0 {
			// We haven't fetched creds yet, so attempt it
			nonTlsConn, err := nonTlsConnFn()
			if err != nil {
				return nil, fmt.Errorf("(%s) unable to dial to server: %w", op, err)
			}

			// log.Println("attempting fetch")
			fetchResp, retErr := attemptFetch(ctx, nonTlsConn, creds, opt...)
			closeErr := nonTlsConn.Close()
			// log.Println("fetch retErr", retErr)
			if closeErr != nil {
				retErr = multierror.Append(retErr, fmt.Errorf("(%s) error closing initial connection: %w", op, closeErr))
			}
			if retErr != nil {
				return nil, retErr
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

		// log.Println(op, "reconnecting")
		nonTlsConn, err := nonTlsConnFn()
		if err != nil {
			return nil, fmt.Errorf("(%s) unable to dial to controller: %w", op, err)
		}

		tlsConfig, err := nodetls.TlsClientConfig(ctx, creds, opt...)
		if err != nil {
			return nil, fmt.Errorf("(%s) unable to get tls config from node creds: %w", op, err)
		}
		tlsConn := tls.Client(nonTlsConn, tlsConfig)
		return tlsConn, nil
	}
}

func attemptFetch(ctx context.Context, nonTlsConn net.Conn, creds *nodetypes.NodeCredentials, opt ...nodee.Option) (*nodetypes.FetchNodeCredentialsResponse, error) {
	const op = "nodee.nodeauth.attemptFetch"

	opts, err := nodee.GetOpts(opt...)
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

	// We need to use TLS for the connection but we aren't relying on its
	// security. Create a self-signed cert and embed our info into it.
	template := &x509.Certificate{
		AuthorityKeyId: creds.CertificatePublicKeyPkix,
		SubjectKeyId:   creds.CertificatePublicKeyPkix,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:              []string{nodee.CommonDnsName},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(mathrand.Int63()),
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(5 * time.Minute),
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
		// We are using TLS as transport for signed, public information only; we do
		// not rely on it for security
		InsecureSkipVerify: true,
		NextProtos:         nodetls.BreakIntoNextProtos(nodee.FetchNodeCredsNextProtoV1Prefix, reqMsgString),
	}

	tlsConn := tls.Client(nonTlsConn, tlsConf)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("(%s) error tls handshaking connection: %w", op, err)
	}

	fetchResp := new(nodetypes.FetchNodeCredentialsResponse)

	// If the common name is the global one, there was no data to return
	commonName := tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName
	if commonName != nodee.CommonDnsName {
		respBytes, err := base64.RawStdEncoding.DecodeString(tlsConn.ConnectionState().PeerCertificates[0].Subject.CommonName)
		if err != nil {
			return nil, fmt.Errorf("(%s) error base64 decoding fetch response: %w", op, err)
		}
		if err := proto.Unmarshal(respBytes, fetchResp); err != nil {
			return nil, fmt.Errorf("(%s) error decoding response from server: %w", op, err)
		}
	}

	return fetchResp, nil
}
