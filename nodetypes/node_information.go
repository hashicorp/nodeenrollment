package nodetypes

import (
	"context"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	nodee "github.com/hashicorp/nodeenrollment"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
)

var _ nodee.X25519Producer = (*NodeInformation)(nil)

// Store stores node information to server storage, wrapping values along the
// way if given a wrapper
//
// Supported options: WithWrapper
func (n *NodeInformation) Store(ctx context.Context, storage nodee.Storage, opt ...nodee.Option) error {
	const op = "nodee.nodetypes.(NodeInformation).Store"

	if n.Id == "" {
		return fmt.Errorf("(%s) node is missing id", op)
	}

	opts, err := nodee.GetOpts(opt...)
	if err != nil {
		return fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	infoToStore := n
	if opts.WithWrapper != nil {
		keyId, err := opts.WithWrapper.KeyId(ctx)
		if err != nil {
			return fmt.Errorf("(%s) error reading wrapper key id: %w", op, err)
		}
		n.WrappingKeyId = keyId
		infoToStore = proto.Clone(n).(*NodeInformation)

		blobInfo, err := opts.WithWrapper.Encrypt(
			ctx,
			infoToStore.ServerEncryptionPrivateKeyBytes,
			wrapping.WithAad(infoToStore.CertificatePublicKeyPkix),
		)
		if err != nil {
			return fmt.Errorf("(%s) error wrapping private key: %w", op, err)
		}
		infoToStore.ServerEncryptionPrivateKeyBytes, err = proto.Marshal(blobInfo)
		if err != nil {
			return fmt.Errorf("(%s) error marshaling wrapped private key: %w", op, err)
		}

		if len(infoToStore.RegistrationNonce) != 0 {
			blobInfo, err = opts.WithWrapper.Encrypt(
				ctx,
				[]byte(infoToStore.RegistrationNonce),
				wrapping.WithAad(infoToStore.CertificatePublicKeyPkix),
			)
			if err != nil {
				return fmt.Errorf("(%s) error wrapping registration nonce: %w", op, err)
			}
			infoToStore.RegistrationNonce, err = proto.Marshal(blobInfo)
			if err != nil {
				return fmt.Errorf("(%s) error marshaling wrapped registration nonce: %w", op, err)
			}
		}
	}

	if err := storage.Store(ctx, infoToStore); err != nil {
		return fmt.Errorf("(%s) error storing node information: %w", op, err)
	}

	return nil
}

// LoadNoadInformation loads the node information from storage, unwrapping encrypted
// values if needed.
//
// Supported options: WithWrapper
func LoadNodeInformation(ctx context.Context, storage nodee.Storage, id string, opt ...nodee.Option) (*NodeInformation, error) {
	const op = "nodee.nodetypes.LoadNodeInformation"
	if id == "" {
		return nil, fmt.Errorf("(%s) empty identifier", op)
	}

	opts, err := nodee.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	nodeInfo := &NodeInformation{
		Id: id,
	}
	if err := storage.Load(ctx, nodeInfo); err != nil {
		return nil, fmt.Errorf("(%s) error loading node information from storage: %w", op, err)
	}

	if nodeInfo.WrappingKeyId != "" {
		if opts.WithWrapper == nil {
			return nil, fmt.Errorf("(%s) node information has encrypted parts with wrapper key id %q but wrapper not provided", op, nodeInfo.WrappingKeyId)
		}
		// Note: not checking the wrapper key IDs against each other because if
		// using something like a PooledWrapper then the current encryping ID
		// may not match, or if the wrapper performs its own internal key
		// selection.
		blobInfo := new(wrapping.BlobInfo)
		if err := proto.Unmarshal(nodeInfo.ServerEncryptionPrivateKeyBytes, blobInfo); err != nil {
			return nil, fmt.Errorf("(%s) error unmarshaling private key blob info: %w", op, err)
		}
		pt, err := opts.WithWrapper.Decrypt(ctx, blobInfo, wrapping.WithAad(nodeInfo.CertificatePublicKeyPkix))
		if err != nil {
			return nil, fmt.Errorf("(%s) error decrypting private key: %w", op, err)
		}
		nodeInfo.ServerEncryptionPrivateKeyBytes = pt

		if len(nodeInfo.RegistrationNonce) != 0 {
			blobInfo = new(wrapping.BlobInfo)
			if err := proto.Unmarshal(nodeInfo.RegistrationNonce, blobInfo); err != nil {
				return nil, fmt.Errorf("(%s) error unmarshaling registration nonce blob info: %w", op, err)
			}
			pt, err := opts.WithWrapper.Decrypt(ctx, blobInfo, wrapping.WithAad(nodeInfo.CertificatePublicKeyPkix))
			if err != nil {
				return nil, fmt.Errorf("(%s) error decrypting registration nonce: %w", op, err)
			}
			nodeInfo.RegistrationNonce = pt
		}

		nodeInfo.WrappingKeyId = ""
	}

	return nodeInfo, nil
}

// X25519EncryptionKey uses the NodeInformation's values to produce a shared
// encryption key via X25519
func (n *NodeInformation) X25519EncryptionKey() ([]byte, error) {
	const op = "nodee.nodetypes.(NodeInformation).X25519EncryptionKey"

	switch {
	case len(n.ServerEncryptionPrivateKeyBytes) == 0:
		return nil, fmt.Errorf("(%s) encryption private key bytes is empty", op)
	case n.ServerEncryptionPrivateKeyType != KEYTYPE_KEYTYPE_X25519:
		return nil, fmt.Errorf("(%s) encryption private key type is not known", op)
	case len(n.EncryptionPublicKeyBytes) == 0:
		return nil, fmt.Errorf("(%s) encryption public key bytes is empty", op)
	case n.EncryptionPublicKeyType != KEYTYPE_KEYTYPE_X25519:
		return nil, fmt.Errorf("(%s) encryption public key type is not known", op)
	}
	return curve25519.X25519(n.ServerEncryptionPrivateKeyBytes, n.EncryptionPublicKeyBytes)
}
