package tls

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/nodeenrollment"
)

// standardTlsConfig returns a tls config suitable for either client or server
// use with our custom settings/verification logic
//
// Generally this will not be used on its own, but will be called by other parts
// of the library that will further customize the configuration and provide
// appropriate roots.
//
// Supported options: WithRandReader, WithNonce, WithVerifyConnectionFunc,
// WithExpectedPublicKey, WithServerName
func standardTlsConfig(ctx context.Context, tlsCerts []tls.Certificate, pool *x509.CertPool, opt ...nodeenrollment.Option) (*tls.Config, error) {
	const op = "nodeenrollment.tls.standardTlsConfig"

	switch {
	case len(tlsCerts) == 0:
		return nil, fmt.Errorf("(%s) no tls certificates provided", op)
	case pool == nil:
		return nil, fmt.Errorf("(%s) nil ca pool provided", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	verifyOpts := x509.VerifyOptions{
		DNSName: nodeenrollment.CommonDnsName,
		Roots:   pool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}
	if opts.WithNonce != "" {
		verifyOpts.DNSName = opts.WithNonce
	}
	if opts.WithTlsVerifyOptionsFunc != nil {
		verifyOpts = opts.WithTlsVerifyOptionsFunc(pool)
	}

	tlsConfig := &tls.Config{
		Rand:               opts.WithRandomReader,
		ClientAuth:         tls.RequireAnyClientCert,
		MinVersion:         tls.VersionTLS13,
		Certificates:       tlsCerts,
		RootCAs:            pool,
		ClientCAs:          pool,
		InsecureSkipVerify: true,
		ServerName:         opts.WithServerName,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("(%s) no peer certificates in VerifyConnection", op)
			}
			if opts.WithAlpnProtoPrefix == nodeenrollment.FetchNodeCredsNextProtoV1Prefix {
				// We are always skipping verification in this case as we either
				// are returning unauthorized or are returning an encrypted
				// value.
				return nil
			}
			var retErr *multierror.Error
			for _, cert := range cs.PeerCertificates {
				if _, err := cert.Verify(verifyOpts); err != nil {
					retErr = multierror.Append(retErr, err)
					continue
				}
				if len(opts.WithExpectedPublicKey) != 0 {
					if subtle.ConstantTimeCompare(opts.WithExpectedPublicKey, cert.SubjectKeyId) != 1 {
						retErr = multierror.Append(retErr, fmt.Errorf("(%s) subject key ID does not match", op))
						continue
					}
				}
				return nil
			}
			return fmt.Errorf("(%s) errors verifying certificates: %w", op, retErr)
		},
	}

	return tlsConfig, nil
}
