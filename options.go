package nodee

import (
	"crypto/rand"
	"crypto/x509"
	"io"
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// GetOpts iterates the inbound Options and returns a struct
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

type Options struct {
	WithDuration             time.Duration
	WithRandomReader         io.Reader
	WithNonce                string
	WithTlsVerifyOptionsFunc func(*x509.CertPool) x509.VerifyOptions
	WithWrapper              wrapping.Wrapper
	WithSkipStorage          bool
	WithSkipVerifyConnection bool
	WithExpectedPublicKey    []byte
}

// Option is a function that takes in an options struct and sets values or
// returns an error.
type Option func(*Options) error

func getDefaultOptions() *Options {
	return &Options{
		WithDuration:     DefaultDuration,
		WithRandomReader: rand.Reader,
	}
}

// WithDuration allows creating a certificate with the given lifetime rather
// than the default.
func WithDuration(with time.Duration) Option {
	return func(o *Options) error {
		o.WithDuration = with
		return nil
	}
}

// WithRandomReader allows specifying a reader to use in place of the default
// (crypto/rand)
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

// WithTlsVerifyOptionsFunc allows specifying a custom TLS certificate VerifyFunc,
// useful for testing
func WithTlsVerifyOptionsFunc(with func(*x509.CertPool) x509.VerifyOptions) Option {
	return func(o *Options) error {
		o.WithTlsVerifyOptionsFunc = with
		return nil
	}
}

// WithWrapper will cause the library to wrap any sensitive information (private
// keys) with the given wrapper prior to writing to storage, and to unwrap when
// reading from storage.
func WithWrapper(with wrapping.Wrapper) Option {
	return func(o *Options) error {
		o.WithWrapper = with
		return nil
	}
}

// WithSkipStorage allows indicating that the newly generated resource should
// not be stored in storage, but simply returned in-memory only.
func WithSkipStorage(with bool) Option {
	return func(o *Options) error {
		o.WithSkipStorage = with
		return nil
	}
}

// WithSkipVerifyConnection allows indicating that the VerifyConnection function
// should be nil, useful on fetch
func WithSkipVerifyConnection(with bool) Option {
	return func(o *Options) error {
		o.WithSkipVerifyConnection = with
		return nil
	}
}

// WithExpectedPublicKey allows indicating a public key that we expect to be the
// signed key on a certificate
func WithExpectedPublicKey(with []byte) Option {
	return func(o *Options) error {
		o.WithExpectedPublicKey = with
		return nil
	}
}
