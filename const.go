package nodeenrollment

import (
	"errors"
	"time"
)

type KnownId string

const (
	// CurrentId is a const for when we are fetching the "current" value for
	// various purposes
	CurrentId KnownId = "current"

	// NextId is a const for when we are fetching the "next" value for various
	// purposes
	NextId KnownId = "next"
)

const (
	// DefaultCertificateLifetime is the default duration of a certificate, set
	// to two weeks. Rotations should happen at roughly half this.
	DefaultCertificateLifetime = time.Hour * 24 * 14

	// CommonDnsName is a name we can use in the absence of anything more
	// specific. In most cases we actually do not care about common name or DNS
	// SAN verification, and when we do we have an explicit test for it. In all
	// other cases using this allows us to not fail due to name validity checks.
	// Derived loosely from the Wizard in The Wizard of Oz.
	CommonDnsName = "pay-no-attention-to-that-pers-on-behind-the-curt-on"

	// FetchNodeCredsNextProtoV1Prefix is the ALPN NextProto used when a node is
	// trying to fetch credentials
	FetchNodeCredsNextProtoV1Prefix = "v1-nodee-fetch-node-creds-"

	// AuthenticateNodeNextProtoV1Prefix is the ALPN NextProto used when a node
	// is trying to authenticate
	AuthenticateNodeNextProtoV1Prefix = "v1-nodee-authenticate-node-"

	// NonceSize is our defined nonce size, in bytes
	NonceSize = 32

	// KeyIdNumWords is the number of words to generate from a hash of the
	// public key to serve as the key ID
	KeyIdNumWords = 8
)

// ErrNotFound is a common error to use when a value is not found in storage.
// Depending on the storage implementation it may be a different underlying
// error, so this ensures we can use errors.Is as a check.
var ErrNotFound = errors.New("value not found in storage")
