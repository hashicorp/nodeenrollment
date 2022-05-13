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
// values along the way
//
// Supported options: WithWrapper
func (r *RootCertificate) Store(ctx context.Context, storage nodeenrollment.Storage, opt ...nodeenrollment.Option) error {
	const op = "nodeenrollment.nodetypes.(RootCertificate).Store"

	switch r.Id {
	case "":
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

// LoadRootCertificate loads the certificate from storage, unwrapping encrypted
// values if needed
//
// Supported options: WithWrapper
func LoadRootCertificate(ctx context.Context, storage nodeenrollment.Storage, id string, opt ...nodeenrollment.Option) (*RootCertificate, error) {
	const op = "nodeenrollment.nodetypes.LoadRootCertificate"

	switch id {
	case "":
		return nil, fmt.Errorf("(%s) root is missing id", op)
	case nodeenrollment.CurrentId, nodeenrollment.NextId:
	default:
		return nil, fmt.Errorf("(%s) invalid root certificate id", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	root := &RootCertificate{
		Id: id,
	}
	if err := storage.Load(ctx, root); err != nil {
		return nil, fmt.Errorf("(%s) error loading certificate from storage: %w", op, err)
	}

	if root.WrappingKeyId != "" {
		if opts.WithWrapper == nil {
			return nil, fmt.Errorf("(%s) certificate has encrypted parts with wrapper key id %q but wrapper not provided", op, root.WrappingKeyId)
		}
		// Note: not checking the key IDs against each other because if using
		// something like a PooledWrapper then the current encryping ID may not
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
	const op = "nodeenrollment.nodetypes.LoadRootCertificates"
	ret := new(RootCertificates)
	for _, id := range []string{nodeenrollment.CurrentId, nodeenrollment.NextId} {
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

func (r *RootCertificate) SigningParams(ctx context.Context) (*x509.Certificate, crypto.Signer, error) {
	const op = "nodeenrollment.nodetypes.(RootCertificate).SigningParams"
	switch {
	case len(r.PrivateKeyPkcs8) == 0:
		return nil, nil, fmt.Errorf("(%s) no private key found in root", op)
	case r.PrivateKeyType == KEYTYPE_KEYTYPE_UNSPECIFIED:
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
		case KEYTYPE_KEYTYPE_ED25519:
			raw, err := x509.ParsePKCS8PrivateKey(r.PrivateKeyPkcs8)
			if err != nil {
				return nil, nil, fmt.Errorf("(%s) error unmarshaling private key: %w", op, err)
			}
			signer = raw.(ed25519.PrivateKey)
		default:
			return nil, nil, fmt.Errorf("(%s) unknown private key type %v", op, r.PrivateKeyType.String())
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
