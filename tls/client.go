// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tls

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/proto"
)

// ClientConfig creates a client-side tls.Config by from the given
// NodeCredentials. The values populated here can be used or modified as needed.
//
// Supported options: WithRandomReader, WithServerName (passed through to
// standardTlsConfig), WithExtraAlpnProtos, WithState
func ClientConfig(ctx context.Context, n *types.NodeCredentials, opt ...nodeenrollment.Option) (*tls.Config, error) {
	const op = "nodeenrollment.tls.ClientConfig"

	switch {
	case n == nil:
		return nil, fmt.Errorf("(%s) nil input", op)
	case len(n.CertificatePrivateKeyPkcs8) == 0:
		return nil, fmt.Errorf("(%s) no certificate private key", op)
	case n.CertificatePrivateKeyType != types.KEYTYPE_ED25519:
		return nil, fmt.Errorf("(%s) unsupported certificate private key type %s", op, n.CertificatePrivateKeyType.String())
	case len(n.CertificateBundles) != 2:
		return nil, fmt.Errorf("(%s) invalid certificate bundles found in credentials, wanted 2, got %d", op, len(n.CertificateBundles))
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	var signer crypto.Signer
	// Parse certificate private key
	{
		key, err := x509.ParsePKCS8PrivateKey(n.CertificatePrivateKeyPkcs8)
		switch {
		case err != nil:
			return nil, fmt.Errorf("(%s) error parsing certificate private key bytes: %w", op, err)
		case key == nil:
			return nil, fmt.Errorf("(%s) nil key after parsing certificate private key bytes", op)
		case n.CertificatePrivateKeyType == types.KEYTYPE_ED25519:
			var ok bool
			if signer, ok = key.(ed25519.PrivateKey); !ok {
				return nil, fmt.Errorf("(%s) certificate key cannot be understood as ed25519 private key", op)
			}
		default:
			return nil, fmt.Errorf("(%s) after parsing certificate private key information no signer found", op)
		}
	}

	nonceBytes := make([]byte, nodeenrollment.NonceSize)
	w, err := opts.WithRandomReader.Read(nonceBytes)
	if err != nil {
		return nil, fmt.Errorf("(%s) error generating nonce: %w", op, err)
	}
	if w != nodeenrollment.NonceSize {
		return nil, fmt.Errorf("(%s) invalid number of nonce bytes read, expected %d, got %d", op, nodeenrollment.NonceSize, w)
	}
	sigNonceBytes, err := signer.Sign(opts.WithRandomReader, nonceBytes, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("(%s) error signing certs request nonce: %w", op, err)
	}

	var clientStateBytes []byte
	var sigClientStateBytes []byte
	if opts.WithState != nil {
		clientStateBytes, err = proto.Marshal(opts.WithState)
		if err != nil {
			return nil, fmt.Errorf("(%s) error marshaling client state: %w", op, err)
		}
		sigClientStateBytes, err = signer.Sign(opts.WithRandomReader, clientStateBytes, crypto.Hash(0))
		if err != nil {
			return nil, fmt.Errorf("(%s) error signing certs request client state: %w", op, err)
		}
	}

	// This may seem like an unintuitive name given this is a client, but it's
	// really a request for the other side to present a server cert that is
	// valid and with the embedded nonce.
	req := &types.GenerateServerCertificatesRequest{
		CertificatePublicKeyPkix: n.CertificatePublicKeyPkix,
		Nonce:                    nonceBytes,
		NonceSignature:           sigNonceBytes,
		ClientState:              clientStateBytes,
		ClientStateSignature:     sigClientStateBytes,
	}
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("(%s) error marshaling certs request: %w", op, err)
	}
	reqStr := base64.RawStdEncoding.EncodeToString(reqBytes)

	rootPool := x509.NewCertPool()
	var tlsCerts []tls.Certificate

	var foundCert bool
	now := time.Now()
	var leafX509 *x509.Certificate
	for _, certBundle := range n.CertificateBundles {
		if foundCert {
			break
		}

		// Parse node certificate
		{
			var err error
			leafX509, err = x509.ParseCertificate(certBundle.CertificateDer)
			if err != nil {
				return nil, fmt.Errorf("(%s) error parsing node certificate bytes: %w", op, err)
			}
			if leafX509 == nil {
				return nil, fmt.Errorf("(%s) after parsing node cert found empty value", op)
			}
			// It's expired
			if leafX509.NotAfter.Before(now) {
				continue
			}
			// It's not yet valid
			if leafX509.NotBefore.After(now) {
				continue
			}
		}

		// Parse CA certificate
		{
			serverCert, err := x509.ParseCertificate(certBundle.CaCertificateDer)
			if err != nil {
				return nil, fmt.Errorf("(%s) error parsing server certificate bytes: %w", op, err)
			}
			if serverCert == nil {
				return nil, fmt.Errorf("(%s) after parsing server cert found empty value", op)
			}
			// It's expired
			if serverCert.NotAfter.Before(now) {
				continue
			}
			// It's not yet valid
			if serverCert.NotBefore.After(now) {
				continue
			}
			rootPool.AddCert(serverCert)
		}

		tlsCerts = append(tlsCerts, tls.Certificate{
			Certificate: [][]byte{
				certBundle.CertificateDer,
				certBundle.CaCertificateDer,
			},
			PrivateKey: signer,
			Leaf:       leafX509,
		})

		foundCert = true
	}

	if len(tlsCerts) == 0 {
		return nil, fmt.Errorf("(%s) no valid client certificates found", op)
	}

	// Require nonce in DNS names in verification function
	opt = append(opt, nodeenrollment.WithNonce(base64.RawStdEncoding.EncodeToString(nonceBytes)))

	tlsConfig, err := standardTlsConfig(ctx, tlsCerts, rootPool, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error fetching standard tls config: %w", op, err)
	}

	tlsConfig.NextProtos, err = BreakIntoNextProtos(nodeenrollment.AuthenticateNodeNextProtoV1Prefix, reqStr)
	if err != nil {
		return nil, fmt.Errorf("(%s) error breaking request into next protos: %w", op, err)
	}
	tlsConfig.NextProtos = append(tlsConfig.NextProtos, opts.WithExtraAlpnProtos...)
	return tlsConfig, nil
}
