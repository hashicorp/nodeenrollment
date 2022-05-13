package rotation

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"time"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// RotateRootCertificates generates a new private key and self-signed CA root
// certificate. Despite the name, this function only rotates the current root
// certificate if there are already two in existence. Otherwise, the current
// root remains the same and the next root is staged. The idea here is to call
// it periodically at half the desired rotation interval: if the interval should
// be two weeks, call it once a week. The first call will stage the next root;
// the next call, at two weeks, will then rotate both, and a call each week
// after that will rotate again.
//
// Supported options: WithCertificateLifetiem, WithRandomReader, WithHostname,
// WithWrapper (passed through to RootCertificate.Store), WithSkipStorage
func RotateRootCertificates(ctx context.Context, storage nodeenrollment.Storage, opt ...nodeenrollment.Option) (*types.RootCertificates, error) {
	const op = "nodeenrollment.rotation.RotateRootCertificate"
	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	// Check our existing state
	var currentRoot, nextRoot *types.RootCertificate
	nextRoot, err = types.LoadRootCertificate(ctx, storage, nodeenrollment.NextId)
	if err != nil && !errors.Is(err, nodeenrollment.ErrNotFound) {
		return nil, fmt.Errorf("(%s) error checking for existing next root: %w", op, err)
	}
	currentRoot, err = types.LoadRootCertificate(ctx, storage, nodeenrollment.NextId)
	if err != nil && !errors.Is(err, nodeenrollment.ErrNotFound) {
		return nil, fmt.Errorf("(%s) error checking for existing current root: %w", op, err)
	}

	var nextCurrent, nextNext *types.RootCertificate
	toMake := make([]string, 0, 2)
	// Decide what to do
	switch {
	case currentRoot == nil && nextRoot == nil:
		toMake = append(toMake, nodeenrollment.CurrentId, nodeenrollment.NextId)

	case currentRoot == nil:
		// We have no current but we have next? Shouldn't happen, but pull next
		// forward and make a new next
		nextCurrent = nextRoot
		toMake = append(toMake, nodeenrollment.NextId)

	case nextRoot == nil:
		// This also shouldn't happen, but it's more obviously recoverable --
		// make a new next
		toMake = append(toMake, nodeenrollment.NextId)

	default:
		nextCurrent = nextRoot
		toMake = append(toMake, nodeenrollment.NextId)
	}

	for _, kind := range toMake {
		var (
			newRoot = new(types.RootCertificate)
			pubKey  ed25519.PublicKey
			privKey ed25519.PrivateKey
		)
		// Create certificate key
		{
			pubKey, privKey, err = ed25519.GenerateKey(opts.WithRandomReader)
			if err != nil {
				return nil, fmt.Errorf("(%s) error generating certificate keypair: %w", op, err)
			}

			newRoot.PrivateKeyPkcs8, err = x509.MarshalPKCS8PrivateKey(privKey)
			if err != nil {
				return nil, fmt.Errorf("(%s) error marshaling certificate private key: %w", op, err)
			}
			newRoot.PrivateKeyType = types.KEYTYPE_KEYTYPE_ED25519

			newRoot.PublicKeyPkix, _, err = nodeenrollment.SubjectKeyInfoAndKeyIdFromPubKey(pubKey)
			if err != nil {
				return nil, fmt.Errorf("(%s) error fetching public key id: %w", op, err)
			}
		}

		// Generate certificate
		{
			template := &x509.Certificate{
				AuthorityKeyId:        newRoot.PublicKeyPkix,
				SubjectKeyId:          newRoot.PublicKeyPkix,
				DNSNames:              []string{nodeenrollment.CommonDnsName},
				KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
				SerialNumber:          big.NewInt(mathrand.Int63()),
				NotBefore:             time.Now().Add(-5 * time.Minute),
				NotAfter:              time.Now().Add(opts.WithCertificateLifetime),
				BasicConstraintsValid: true,
				IsCA:                  true,
			}

			if kind == nodeenrollment.NextId {
				newRoot.Id = nodeenrollment.NextId
				nextNext = newRoot
				if len(toMake) == 2 {
					// Making two at once, so current will be the current time
					// period and next will be shifted
					template.NotBefore = template.NotBefore.Add(opts.WithCertificateLifetime / 2)
					template.NotAfter = template.NotAfter.Add(opts.WithCertificateLifetime / 2)
				}
			} else {
				newRoot.Id = nodeenrollment.CurrentId
				nextCurrent = newRoot
			}

			newRoot.NotBefore = timestamppb.New(template.NotBefore)
			newRoot.NotAfter = timestamppb.New(template.NotAfter)

			newRoot.CertificateDer, err = x509.CreateCertificate(opts.WithRandomReader, template, template, pubKey, privKey)
			if err != nil {
				return nil, fmt.Errorf("(%s) error creating certificate: %w", op, err)
			}
		}
	}

	if !opts.WithSkipStorage {
		if err := nextCurrent.Store(ctx, storage, opt...); err != nil {
			return nil, fmt.Errorf("(%s) error persisting current root certificate: %w", op, err)
		}
		if err := nextNext.Store(ctx, storage, opt...); err != nil {
			return nil, fmt.Errorf("(%s) error persisting next root certificate: %w", op, err)
		}
	}

	return &types.RootCertificates{
		Current: nextCurrent,
		Next:    nextNext,
	}, nil
}
