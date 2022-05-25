package types

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment"
	"google.golang.org/protobuf/proto"
)

// Store stores the certificate to the given storage, possibly encrypting secret
// values along the way if a wrapper is passed
//
// Supported options: WithWrapper
func (r *RootCertificate) Store(ctx context.Context, storage nodeenrollment.Storage, opt ...nodeenrollment.Option) error {
	const op = "nodeenrollment.types.(RootCertificate).Store"

	switch {
	case nodeenrollment.IsNil(storage):
		return fmt.Errorf("(%s) storage is nil", op)

	case nodeenrollment.IsNil(r):
		return fmt.Errorf("(%s) root certificate is nil", op)

	case len(r.PrivateKeyPkcs8) == 0:
		// This isn't really a validation function, but we want to avoid
		// wrapping a nil key so we do a check here
		return fmt.Errorf("(%s) refusing to store root with no private key", op)
	}

	switch nodeenrollment.KnownId(r.Id) {
	case nodeenrollment.MissingId:
		return fmt.Errorf("(%s) root is missing id", op)
	case nodeenrollment.CurrentId, nodeenrollment.NextId:
	default:
		return fmt.Errorf("(%s) invalid root certificate id", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	certToStore := r
	if opts.WithWrapper != nil {
		keyId, err := opts.WithWrapper.KeyId(ctx)
		if err != nil {
			return fmt.Errorf("(%s) error reading wrapper key id: %w", op, err)
		}
		r.WrappingKeyId = keyId
		certToStore = proto.Clone(r).(*RootCertificate)

		blobInfo, err := opts.WithWrapper.Encrypt(
			ctx,
			certToStore.PrivateKeyPkcs8,
			wrapping.WithAad(certToStore.PublicKeyPkix),
		)
		if err != nil {
			return fmt.Errorf("(%s) error wrapping private key: %w", op, err)
		}
		certToStore.PrivateKeyPkcs8, err = proto.Marshal(blobInfo)
		if err != nil {
			return fmt.Errorf("(%s) error marshaling wrapped private key: %w", op, err)
		}
	}

	if err := storage.Store(ctx, certToStore); err != nil {
		return fmt.Errorf("(%s) error storing root certificate: %w", op, err)
	}

	return nil
}

// LoadRootCertificate loads the RootCertificate from storage, unwrapping
// encrypted values if needed
//
// Supported options: WithWrapper
func LoadRootCertificate(ctx context.Context, storage nodeenrollment.Storage, id nodeenrollment.KnownId, opt ...nodeenrollment.Option) (*RootCertificate, error) {
	const op = "nodeenrollment.types.LoadRootCertificate"

	switch id {
	case nodeenrollment.MissingId:
		return nil, fmt.Errorf("(%s) missing id", op)
	case nodeenrollment.CurrentId, nodeenrollment.NextId:
	default:
		return nil, fmt.Errorf("(%s) invalid id", op)
	}

	if nodeenrollment.IsNil(storage) {
		return nil, fmt.Errorf("(%s) storage is nil", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	root := &RootCertificate{
		Id: string(id),
	}
	if err := storage.Load(ctx, root); err != nil {
		return nil, fmt.Errorf("(%s) error loading certificate from storage: %w", op, err)
	}

	switch {
	case opts.WithWrapper == nil && root.WrappingKeyId != "":
		return nil, fmt.Errorf("(%s) root has encrypted parts with wrapper key id %q but wrapper not provided", op, root.WrappingKeyId)
	case root.WrappingKeyId != "":
		// Note: not checking the key IDs against each other because if using
		// something like a PooledWrapper then the current encrypting ID may not
		// match, or if the wrapper performs its own internal key selection.
		blobInfo := new(wrapping.BlobInfo)
		if err := proto.Unmarshal(root.PrivateKeyPkcs8, blobInfo); err != nil {
			return nil, fmt.Errorf("(%s) error unmarshaling private key blob info: %w", op, err)
		}
		pt, err := opts.WithWrapper.Decrypt(
			ctx,
			blobInfo,
			wrapping.WithAad(root.PublicKeyPkix),
		)
		if err != nil {
			return nil, fmt.Errorf("(%s) error decrypting private key: %w", op, err)
		}
		root.PrivateKeyPkcs8 = pt
		root.WrappingKeyId = ""
	}

	return root, nil
}

// LoadRootCertificates is a shortcut for calling LoadRootCertificate twice with
// nodeenrollment.CurrentId and nodeenrollment.NextId
func LoadRootCertificates(ctx context.Context, storage nodeenrollment.Storage, opt ...nodeenrollment.Option) (*RootCertificates, error) {
	const op = "nodeenrollment.types.LoadRootCertificates"

	if nodeenrollment.IsNil(storage) {
		return nil, fmt.Errorf("(%s) nil storage", op)
	}

	ret := new(RootCertificates)
	for _, id := range []nodeenrollment.KnownId{nodeenrollment.CurrentId, nodeenrollment.NextId} {
		root, err := LoadRootCertificate(ctx, storage, id, opt...)
		if err != nil {
			return nil, fmt.Errorf("(%s) error loading root certificate: %w", op, err)
		}
		switch id {
		case nodeenrollment.CurrentId:
			ret.Current = root
		default:
			ret.Next = root
		}
	}
	return ret, nil
}

// SigningParams is a helper to extract the necessary information from the
// RootCertificate to use as a CA certificate
func (r *RootCertificate) SigningParams(ctx context.Context) (*x509.Certificate, crypto.Signer, error) {
	const op = "nodeenrollment.types.(RootCertificate).SigningParams"
	switch {
	case nodeenrollment.IsNil(r):
		return nil, nil, fmt.Errorf("(%s) root certificate is nil", op)
	case len(r.PrivateKeyPkcs8) == 0:
		return nil, nil, fmt.Errorf("(%s) no private key found in root", op)
	case r.PrivateKeyType == KEYTYPE_UNSPECIFIED:
		return nil, nil, fmt.Errorf("(%s) private key type information not found in root", op)
	case len(r.CertificateDer) == 0:
		return nil, nil, fmt.Errorf("(%s) no certificate found in root", op)
	}

	var (
		signer crypto.Signer
		cert   *x509.Certificate
	)

	// Parse private key
	{
		switch r.PrivateKeyType {
		case KEYTYPE_ED25519:
			raw, err := x509.ParsePKCS8PrivateKey(r.PrivateKeyPkcs8)
			if err != nil {
				return nil, nil, fmt.Errorf("(%s) error unmarshaling private key: %w", op, err)
			}
			var ok bool
			signer, ok = raw.(ed25519.PrivateKey)
			if !ok {
				return nil, nil, fmt.Errorf("(%s) unmarshalled private key is not expected type, has type %T", op, raw)
			}

		default:
			return nil, nil, fmt.Errorf("(%s) unsupported private key type %v", op, r.PrivateKeyType.String())
		}
	}

	// Parse certificate
	{
		var err error
		cert, err = x509.ParseCertificate(r.CertificateDer)
		switch {
		case err != nil:
			return nil, nil, fmt.Errorf("(%s) error parsing certificate bytes: %w", op, err)
		case cert == nil:
			return nil, nil, fmt.Errorf("(%s) nil key after parsing certificate bytes", op)
		}
	}

	return cert, signer, nil
}
