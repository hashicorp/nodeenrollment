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

// RotateRootCertificates generates roots: private keys and self-signed CA root
// certificates. At the end of this function, there should always be two
// certificates in existence. Howe we get there depends on the current state;
// see the switch statement below.
//
// If things seem off in a way that this function should not allow to occur (for
// instance, one root is missing, or timing is weird), err on the side of
// failing secure and redo the roots.
//
// It is safe to call this periodically; if the current root is still valid and
// no issues are detected with next, nothing will change.
//
// Supported options: WithRandomReader, WithCertificateLifetime, WithWrapper
// (passed through to RootCertificate.Store), WithSkipStorage
func RotateRootCertificates(ctx context.Context, storage nodeenrollment.Storage, opt ...nodeenrollment.Option) (*types.RootCertificates, error) {
	const op = "nodeenrollment.rotation.RotateRootCertificates"
	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	// Check our existing state. We don't use LoadRootCertificates because that
	// errors on one certificate not found and we want to check that scenario.
	var currentRoot, nextRoot *types.RootCertificate
	currentRoot, err = types.LoadRootCertificate(ctx, storage, nodeenrollment.CurrentId)
	if err != nil && !errors.Is(err, nodeenrollment.ErrNotFound) {
		return nil, fmt.Errorf("(%s) error checking for existing current root: %w", op, err)
	}
	nextRoot, err = types.LoadRootCertificate(ctx, storage, nodeenrollment.NextId)
	if err != nil && !errors.Is(err, nodeenrollment.ErrNotFound) {
		return nil, fmt.Errorf("(%s) error checking for existing next root: %w", op, err)
	}

	var toMake []string
	var nextCurrent, nextNext *types.RootCertificate
	toMake, nextCurrent = decideWhatToMake(&types.RootCertificates{Current: currentRoot, Next: nextRoot})
	switch {
	case len(toMake) == 0:
		return &types.RootCertificates{
			Current: currentRoot,
			Next:    nextRoot,
		}, nil

	case len(toMake) == 1 && nextCurrent == nil:
		return nil, fmt.Errorf("(%s) only one certificate to make but next current certificate not determined", op)
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
				// We want to shift next, but we can't do it blindly, in case
				// they didn't call this often enough. So we have to look at the
				// current root to ensure we have overlap. What we do is shift
				// NotBefore and NotAfter by half the remaining lifetime on the
				// current certificate.
				//
				// Note that nextCurrent should always be valid; it was either
				// set in the decideWhatToMake function or we have created a new
				// root already via toMake and set it.
				shift := nextCurrent.NotAfter.AsTime().Sub(time.Now()) / 2
				template.NotBefore = template.NotBefore.Add(shift)
				template.NotAfter = template.NotAfter.Add(shift)
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

// decideWhatToMake examines the current certs and figures out what to create,
// and if only Next which cert (exisitng or next) should be the next current
func decideWhatToMake(in *types.RootCertificates) ([]string, *types.RootCertificate) {
	var toMake []string
	var nextCurrent *types.RootCertificate
	now := time.Now()
	switch {
	case in.Current == nil && in.Next == nil:
		// We don't have either, fresh storage, so we are bootstrapping
		toMake = append(toMake, nodeenrollment.CurrentId, nodeenrollment.NextId)

	case in.Current == nil || in.Next == nil:
		// Shouldn't happen; rather than try to figure out timing of what's
		// there since we have obviously bogus data, start over
		toMake = append(toMake, nodeenrollment.CurrentId, nodeenrollment.NextId)

	case in.Current.NotBefore.AsTime().After(now):
		// We somehow have a current cert that isn't valid yet; start over
		toMake = append(toMake, nodeenrollment.CurrentId, nodeenrollment.NextId)

	case in.Current.NotAfter.AsTime().Before(now):
		if in.Next.NotBefore.AsTime().Before(now) && in.Next.NotAfter.AsTime().After(now) {
			// Our current cert has expired but next is still valid; rotate that
			// to current and create a new next
			nextCurrent = in.Next
			toMake = append(toMake, nodeenrollment.NextId)
		} else {
			// Both are expired, or somehow current has expired and next hasn't;
			// start over
			toMake = append(toMake, nodeenrollment.CurrentId, nodeenrollment.NextId)
		}

	default:
		// We have two certs and current is still valid. Verify we're in the
		// appropriate time period for next; if not, keep things as they are.
		switch {
		case in.Next.NotAfter.AsTime().Before(now):
			// Something is weird; current is valid, but next has expired; redo
			// next.
			//
			// NOTE: This case should come before the next one, otherwise
			// NotBefore might be valid and we may not redo next.
			nextCurrent = in.Current
			toMake = append(toMake, nodeenrollment.NextId)

		case in.Next.NotBefore.AsTime().After(now):
			// NOTE: see comment in case above

			// Not time to rotate yet, so don't
			return nil, nil

		default:
			// Current is valid and next is also currently valid, so time to rotate
			nextCurrent = in.Next
			toMake = append(toMake, nodeenrollment.NextId)
		}
	}
	return toMake, nextCurrent
}
