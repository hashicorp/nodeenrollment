package tls

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

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
// Supported options: WithRandReader, WithNonce, WithVerifyConnectionFunc
func standardTlsConfig(ctx context.Context, tlsCerts []tls.Certificate, pool *x509.CertPool, opt ...nodeenrollment.Option) (*tls.Config, error) {
	const op = "nodeenrollment.tls.standardTlsConfig"
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
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("(%s) no peer certificates in VerifyConnection", op)
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

func BreakIntoNextProtos(prefix, value string) []string {
	var count int
	const maxSize = 200
	ret := make([]string, 0, len(value)/maxSize+1)
	for i := 0; i < len(value); i += maxSize {
		end := i + maxSize
		if end > len(value) {
			end = len(value)
		}
		ret = append(ret, fmt.Sprintf("%s%02d-%s", prefix, count, value[i:end]))
		count++
	}
	return ret
}

func CombineFromNextProtos(prefix string, values []string) string {
	var ret string
	for _, val := range values {
		// Strip that and the number
		ret += strings.TrimPrefix(val, prefix)[3:]
	}
	return ret
}
