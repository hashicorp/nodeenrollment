package nodetls

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/nodetypes"
	"google.golang.org/protobuf/proto"
)

// TlsClientConfig is a helper function to pull out values from the bundle that
// are usable for Go's TLS stack. The values populated here can be used or
// modified as needed.
//
// Supported options: WithRandomReader, WithFetch
func TlsClientConfig(ctx context.Context, n *nodetypes.NodeCredentials, opt ...nodee.Option) (*tls.Config, error) {
	const op = "nodee.nodetls.TlsClientConfig"

	switch {
	case len(n.CertificatePrivateKeyPkcs8) == 0:
		return nil, fmt.Errorf("(%s) no node certificate private key found in credentials", op)
	case n.CertificatePrivateKeyType == nodetypes.KEYTYPE_KEYTYPE_UNSPECIFIED:
		return nil, fmt.Errorf("(%s) node certificate private key type information not found in credentials", op)
	case len(n.CertificateBundles) == 0:
		return nil, fmt.Errorf("(%s) no certificate bundles found in credentials", op)
	}

	opts, err := nodee.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	var privKey crypto.PrivateKey
	// Parse certificate private key
	{
		key, err := x509.ParsePKCS8PrivateKey(n.CertificatePrivateKeyPkcs8)
		switch {
		case err != nil:
			return nil, fmt.Errorf("(%s) error parsing certificate private key bytes: %w", op, err)
		case key == nil:
			return nil, fmt.Errorf("(%s) nil key after parsing certificate private key bytes", op)
		case n.CertificatePrivateKeyType == nodetypes.KEYTYPE_KEYTYPE_ED25519:
			var ok bool
			if privKey, ok = key.(ed25519.PrivateKey); !ok {
				return nil, fmt.Errorf("(%s) ed25519 certificate private key not able to be understood as such", op)
			}
		}

		if privKey == nil {
			return nil, fmt.Errorf("(%s) after parsing certificate private key information no signer found", op)
		}
	}

	nonceBytes := make([]byte, nodee.NonceSize)
	w, err := opts.WithRandomReader.Read(nonceBytes)
	if err != nil {
		return nil, fmt.Errorf("(%s) error generating nonce: %w", op, err)
	}
	if w != nodee.NonceSize {
		return nil, fmt.Errorf("(%s) invalid number of nonce bytes read, expected %d, got %d", op, nodee.NonceSize, w)
	}
	sigBytes, err := privKey.(crypto.Signer).Sign(opts.WithRandomReader, nonceBytes, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("(%s) error signing certs request data: %w", op, err)
	}
	// This may seem like an unintuitive name given this is a client, but it's
	// really a request for the other side to present a server cert that is
	// valid and with the embedded nonce.
	req := &nodetypes.GenerateServerCertificatesRequest{
		CertificatePublicKeyPkix: n.CertificatePublicKeyPkix,
		Nonce:                    nonceBytes,
		NonceSignature:           sigBytes,
	}
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("(%s) error marshaling certs request: %w", op, err)
	}
	reqStr := base64.RawStdEncoding.EncodeToString(reqBytes)

	rootPool := x509.NewCertPool()
	var tlsCerts []tls.Certificate

	for _, certBundle := range n.CertificateBundles {
		var leafX509 *x509.Certificate
		// Parse node certificate
		{
			var err error
			leafX509, err = x509.ParseCertificate(certBundle.NodeCertificateDer)
			if err != nil {
				return nil, fmt.Errorf("(%s) error parsing node certificate bytes: %w", op, err)
			}

			if leafX509 == nil {
				return nil, fmt.Errorf("(%s) after parsing node cert found empty value", op)
			}
		}

		// Parse CA certificate
		{
			serverCert, err := x509.ParseCertificate(certBundle.ServerCertificateDer)
			if err != nil {
				return nil, fmt.Errorf("(%s) error parsing server certificate bytes: %w", op, err)
			}
			if serverCert == nil {
				return nil, fmt.Errorf("(%s) after parsing server cert found empty value", op)
			}
			// log.Println(op, "adding client CA serial", serverCert.SerialNumber.String())
			rootPool.AddCert(serverCert)
		}

		tlsCerts = append(tlsCerts, tls.Certificate{
			Certificate: [][]byte{
				certBundle.NodeCertificateDer,
				certBundle.ServerCertificateDer,
			},
			PrivateKey: privKey,
			Leaf:       leafX509,
		})
	}

	// Require nonce in DNS names in verification function
	opt = append(opt, nodee.WithNonce(base64.RawStdEncoding.EncodeToString(nonceBytes)))

	tlsConfig, err := standardTlsConfig(ctx, tlsCerts, rootPool, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error fetching standard tls config: %w", op, err)
	}

	tlsConfig.NextProtos = BreakIntoNextProtos(nodee.AuthenticateNodeNextProtoV1Prefix, reqStr)
	return tlsConfig, nil
}
