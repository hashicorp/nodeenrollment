package types

import (
	"context"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment"
	"google.golang.org/protobuf/proto"
)

var _ nodeenrollment.X25519Producer = (*NodeInformation)(nil)

// Store stores node information to server storage, wrapping values along the
// way if given a wrapper
//
// Supported options: WithWrapper
func (n *NodeInformation) Store(ctx context.Context, storage nodeenrollment.Storage, opt ...nodeenrollment.Option) error {
	const op = "nodeenrollment.types.(NodeInformation).Store"

	switch {
	case nodeenrollment.IsNil(storage):
		return fmt.Errorf("(%s) storage is nil", op)

	case nodeenrollment.IsNil(n):
		return fmt.Errorf("(%s) node information is nil", op)

	case n.Id == "":
		return fmt.Errorf("(%s) node is missing id", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	infoToStore := n
	if opts.WithWrapper != nil {
		infoToStore = proto.Clone(n).(*NodeInformation)

		keyId, err := opts.WithWrapper.KeyId(ctx)
		if err != nil {
			return fmt.Errorf("(%s) error reading wrapper key id: %w", op, err)
		}
		infoToStore.WrappingKeyId = keyId

		if len(infoToStore.ServerEncryptionPrivateKeyBytes) > 0 {
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
		}
	}

	if err := storage.Store(ctx, infoToStore); err != nil {
		return fmt.Errorf("(%s) error storing node information: %w", op, err)
	}

	return nil
}

// LoadNodeInformation loads the node information from storage, unwrapping encrypted
// values if needed.
//
// Supported options: WithWrapper, WithState
func LoadNodeInformation(ctx context.Context, storage nodeenrollment.Storage, id string, opt ...nodeenrollment.Option) (*NodeInformation, error) {
	const op = "nodeenrollment.types.LoadNodeInformation"

	switch {
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) storage is nil", op)
	case id == "":
		return nil, fmt.Errorf("(%s) missing id", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	nodeInfo := &NodeInformation{
		Id:    id,
		State: opts.WithState,
	}
	if err := storage.Load(ctx, nodeInfo); err != nil {
		return nil, fmt.Errorf("(%s) error loading node information from storage: %w", op, err)
	}

	switch {
	case opts.WithWrapper == nil && nodeInfo.WrappingKeyId != "":
		return nil, fmt.Errorf("(%s) node information has encrypted parts with wrapper key id %q but wrapper not provided", op, nodeInfo.WrappingKeyId)
	case nodeInfo.WrappingKeyId != "":
		// Note: not checking the wrapper key IDs against each other because if
		// using something like a PooledWrapper then the current encrypting ID
		// may not match, or if the wrapper performs its own internal key
		// selection.
		if len(nodeInfo.ServerEncryptionPrivateKeyBytes) > 0 {
			blobInfo := new(wrapping.BlobInfo)
			if err := proto.Unmarshal(nodeInfo.ServerEncryptionPrivateKeyBytes, blobInfo); err != nil {
				return nil, fmt.Errorf("(%s) error unmarshaling private key blob info: %w", op, err)
			}
			pt, err := opts.WithWrapper.Decrypt(ctx, blobInfo, wrapping.WithAad(nodeInfo.CertificatePublicKeyPkix))
			if err != nil {
				return nil, fmt.Errorf("(%s) error decrypting private key: %w", op, err)
			}
			nodeInfo.ServerEncryptionPrivateKeyBytes = pt
		}

		nodeInfo.WrappingKeyId = ""
	}

	return nodeInfo, nil
}

// SetPreviousEncryptionKey will set this NodeInformation's PreviousEncryptionKey field
// using the passed NodeInformation
func (n *NodeInformation) SetPreviousEncryptionKey(oldNodeCredentials *NodeInformation) error {
	const op = "nodeenrollment.types.(NodeInformation).SetPreviousEncryptionKey"
	if oldNodeCredentials == nil {
		return fmt.Errorf("(%s) empty prior node information passed in", op)
	}

	previousEncryptionKey := &EncryptionKey{
		PrivateKeyBytes: oldNodeCredentials.ServerEncryptionPrivateKeyBytes,
		PrivateKeyType:  oldNodeCredentials.ServerEncryptionPrivateKeyType,
		PublicKeyBytes:  oldNodeCredentials.EncryptionPublicKeyBytes,
		PublicKeyType:   oldNodeCredentials.EncryptionPublicKeyType,
	}
	n.PreviousEncryptionKey = previousEncryptionKey

	return nil
}

// X25519EncryptionKey uses the NodeInformation's values to produce a shared
// encryption key via X25519
func (n *NodeInformation) X25519EncryptionKey() ([]byte, error) {
	const op = "nodeenrollment.types.(NodeInformation).X25519EncryptionKey"

	if nodeenrollment.IsNil(n) {
		return nil, fmt.Errorf("(%s) node information is empty", op)
	}

	out, err := X25519EncryptionKey(n.ServerEncryptionPrivateKeyBytes, n.ServerEncryptionPrivateKeyType, n.EncryptionPublicKeyBytes, n.EncryptionPublicKeyType)
	if err != nil {
		return nil, fmt.Errorf("(%s) error deriving encryption key: %w", op, err)
	}
	return out, nil
}

// PreviousKey satisfies the X25519Producer and will produce a shared
// encryption key via X25519 if previous key data is present
func (n *NodeInformation) PreviousKey() ([]byte, error) {
	const op = "nodeenrollment.types.(NodeInformation).PreviousKey"

	if nodeenrollment.IsNil(n) {
		return nil, fmt.Errorf("(%s) node information is empty", op)
	}

	previousKey := n.PreviousEncryptionKey
	if previousKey == nil {
		return nil, fmt.Errorf("(%s) previous key is empty", op)
	}

	out, err := X25519EncryptionKey(previousKey.PrivateKeyBytes, previousKey.PrivateKeyType, previousKey.PublicKeyBytes, previousKey.PublicKeyType)
	if err != nil {
		return nil, fmt.Errorf("(%s) error deriving previous encryption key: %w", op, err)
	}
	return out, nil
}
