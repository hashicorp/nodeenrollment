package nodeenrollment

import (
	"crypto/rand"
	"crypto/x509"
	"io"
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/patrickmn/go-cache"
)

// GetOpts iterates the inbound Options and returns a struct and any errors
func GetOpts(opt ...Option) (*Options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		if err := o(opts); err != nil {
			return nil, err
		}

	}
	return opts, nil
}

// Options contains various options. The values are exported since the options
// are parsed in various other packages.
type Options struct {
	WithCertificateLifetime  time.Duration
	WithRandomReader         io.Reader
	WithNonce                string
	WithTlsVerifyOptionsFunc func(*x509.CertPool) x509.VerifyOptions
	WithWrapper              wrapping.Wrapper
	WithSkipStorage          bool
	WithExpectedPublicKey    []byte
	WithRegistrationCache    *cache.Cache
}

// Option is a function that takes in an options struct and sets values or
// returns an error
type Option func(*Options) error

func getDefaultOptions() *Options {
	return &Options{
		WithCertificateLifetime: DefaultCertificateLifetime,
		WithRandomReader:        rand.Reader,
		WithRegistrationCache:   DefaultRegistrationCache,
	}
}

// WithCertificateLifetime allows overriding a default duration, e.g. for certificate
// creation
func WithCertificateLifetime(with time.Duration) Option {
	return func(o *Options) error {
		o.WithCertificateLifetime = with
		return nil
	}
}

// WithRandomReader allows specifying a reader to use in place of the default
// (crypto/rand.Reader)
func WithRandomReader(with io.Reader) Option {
	return func(o *Options) error {
		o.WithRandomReader = with
		return nil
	}
}

// WithNonce is used at various points for encoding nonces in certs or expecting
// them there
func WithNonce(with string) Option {
	return func(o *Options) error {
		o.WithNonce = with
		return nil
	}
}

// WithTlsVerifyOptionsFunc allows specifying a custom TLS certificate
// VerifyFunc, useful for testing
func WithTlsVerifyOptionsFunc(with func(*x509.CertPool) x509.VerifyOptions) Option {
	return func(o *Options) error {
		o.WithTlsVerifyOptionsFunc = with
		return nil
	}
}

// WithWrapper will cause the library to wrap any sensitive information (private
// keys, nonces, etc.) with the given wrapper prior to writing to storage, and
// to unwrap when reading from storage
func WithWrapper(with wrapping.Wrapper) Option {
	return func(o *Options) error {
		o.WithWrapper = with
		return nil
	}
}

// WithSkipStorage allows indicating that the newly generated resource should
// not be stored in storage, but simply returned in-memory only, useful for
// tests
func WithSkipStorage(with bool) Option {
	return func(o *Options) error {
		o.WithSkipStorage = with
		return nil
	}
}

// WithExpectedPublicKey allows indicating a public key that we expect to be the
// key signed by a certificate
func WithExpectedPublicKey(with []byte) Option {
	return func(o *Options) error {
		o.WithExpectedPublicKey = with
		return nil
	}
}

// WithRegistrationCache allows specifying a registration cache to use,
// especially useful in parallel tests
func WithRegistrationCache(with *cache.Cache) Option {
	return func(o *Options) error {
		o.WithRegistrationCache = with
		return nil
	}
}
