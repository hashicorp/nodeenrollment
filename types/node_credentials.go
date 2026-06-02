// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/subtle"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	_ nodeenrollment.X25519KeyProducer = (*NodeCredentials)(nil)
	_ nodeenrollment.KeyProducer       = (*NodeCredentials)(nil)
)

// Store stores node credentials to storage, wrapping values along the way if
// given a wrapper
//
// Supported options: WithStorageWrapper
func (n *NodeCredentials) Store(ctx context.Context, storage nodeenrollment.Storage, opt ...nodeenrollment.Option) error {
	const op = "nodeenrollment.types.(NodeCredentials).Store"

	switch {
	case nodeenrollment.IsNil(storage):
		return fmt.Errorf("(%s) storage is nil", op)

	case nodeenrollment.IsNil(n):
		return fmt.Errorf("(%s) node credentials is nil", op)

	case len(n.CertificatePrivateKeyPkcs8) == 0:
		return fmt.Errorf("(%s) refusing to store node credentials with no certificate pkcs8 private key", op)

	case len(n.CertificatePublicKeyPkix) == 0:
		// This isn't really a validation function, but we want to avoid
		// wrapping with nil AAD so we do a check here
		return fmt.Errorf("(%s) refusing to store node credentials with no certificate pkix public key", op)

	case len(n.EncryptionPrivateKeyBytes) == 0 && n.MlkemParameters == nil:
		return fmt.Errorf("(%s) refusing to store node credentials with no encryption private key", op)

	case n.Id == "":
		return fmt.Errorf("(%s) missing id", op)
	}

	switch nodeenrollment.KnownId(n.Id) {
	case nodeenrollment.MissingId:
		return fmt.Errorf("(%s) credentials is missing id", op)
	case nodeenrollment.CurrentId, nodeenrollment.NextId:
	default:
		return fmt.Errorf("(%s) invalid node credentials id", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	credsToStore := n
	if opts.WithStorageWrapper != nil {
		credsToStore = proto.Clone(n).(*NodeCredentials)

		keyId, err := opts.WithStorageWrapper.KeyId(ctx)
		if err != nil {
			return fmt.Errorf("(%s) error reading wrapper key id: %w", op, err)
		}
		credsToStore.WrappingKeyId = keyId

		blobInfo, err := opts.WithStorageWrapper.Encrypt(
			ctx,
			credsToStore.CertificatePrivateKeyPkcs8,
			wrapping.WithAad(credsToStore.CertificatePublicKeyPkix),
		)
		if err != nil {
			return fmt.Errorf("(%s) error wrapping certificate private key: %w", op, err)
		}
		credsToStore.CertificatePrivateKeyPkcs8, err = proto.Marshal(blobInfo)
		if err != nil {
			return fmt.Errorf("(%s) error marshaling wrapped certificate private key: %w", op, err)
		}

		if len(credsToStore.EncryptionPrivateKeyBytes) > 0 {
			blobInfo, err = opts.WithStorageWrapper.Encrypt(
				ctx,
				credsToStore.EncryptionPrivateKeyBytes,
				wrapping.WithAad(credsToStore.CertificatePublicKeyPkix),
			)
			if err != nil {
				return fmt.Errorf("(%s) error wrapping encryption private key: %w", op, err)
			}
			credsToStore.EncryptionPrivateKeyBytes, err = proto.Marshal(blobInfo)
			if err != nil {
				return fmt.Errorf("(%s) error marshaling wrapped encryption private key: %w", op, err)
			}
		}

		if len(credsToStore.RegistrationNonce) != 0 {
			blobInfo, err = opts.WithStorageWrapper.Encrypt(
				ctx,
				credsToStore.RegistrationNonce,
				wrapping.WithAad(credsToStore.CertificatePublicKeyPkix),
			)
			if err != nil {
				return fmt.Errorf("(%s) error wrapping registration nonce: %w", op, err)
			}
			credsToStore.RegistrationNonce, err = proto.Marshal(blobInfo)
			if err != nil {
				return fmt.Errorf("(%s) error marshaling wrapped registration nonce: %w", op, err)
			}
		}
		if credsToStore.RegistrationChallenge != nil {
			marshaledRegistrationChallenge, err := proto.Marshal(credsToStore.RegistrationChallenge)
			if err != nil {
				return fmt.Errorf("(%s) error marshaling registration challenge: %w", op, err)
			}
			blobInfo, err = opts.WithStorageWrapper.Encrypt(
				ctx,
				marshaledRegistrationChallenge,
				wrapping.WithAad(credsToStore.CertificatePublicKeyPkix),
			)
			if err != nil {
				return fmt.Errorf("(%s) error wrapping registration challenge: %w", op, err)
			}
			credsToStore.EncryptedRegistrationChallenge, err = proto.Marshal(blobInfo)
			if err != nil {
				return fmt.Errorf("(%s) error marshaling wrapped registration challenge: %w", op, err)
			}
			credsToStore.RegistrationChallenge = nil
		}
		if credsToStore.MlkemParameters != nil {
			marshaledMlkemParameters, err := proto.Marshal(credsToStore.MlkemParameters)
			if err != nil {
				return fmt.Errorf("(%s) error marshaling mlkem parameters: %w", op, err)
			}
			blobInfo, err = opts.WithStorageWrapper.Encrypt(
				ctx,
				marshaledMlkemParameters,
				wrapping.WithAad(credsToStore.CertificatePublicKeyPkix),
			)
			if err != nil {
				return fmt.Errorf("(%s) error wrapping mlkem parameters: %w", op, err)
			}
			credsToStore.EncryptedMlkemParameters, err = proto.Marshal(blobInfo)
			if err != nil {
				return fmt.Errorf("(%s) error marshaling wrapped mlkem parameters: %w", op, err)
			}
			credsToStore.MlkemParameters = nil
		}
	}

	if err := storage.Store(ctx, credsToStore); err != nil {
		return fmt.Errorf("(%s) error storing node credentials: %w", op, err)
	}

	return nil
}

// LoadNodeCredentials loads the node credentials from storage, unwrapping
// encrypted values if needed
//
// Supported options: WithStorageWrapper
func LoadNodeCredentials(ctx context.Context, storage nodeenrollment.Storage, id nodeenrollment.KnownId, opt ...nodeenrollment.Option) (*NodeCredentials, error) {
	const op = "nodeenrollment.types.LoadNodeCredentials"

	if nodeenrollment.IsNil(storage) {
		return nil, fmt.Errorf("(%s) storage is nil", op)
	}

	switch nodeenrollment.KnownId(id) {
	case nodeenrollment.MissingId:
		return nil, fmt.Errorf("(%s) credentials is missing id", op)
	case nodeenrollment.CurrentId, nodeenrollment.NextId:
	default:
		return nil, fmt.Errorf("(%s) invalid node credentials id", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	nodeCreds := &NodeCredentials{
		Id: string(id),
	}
	if err := storage.Load(ctx, nodeCreds); err != nil {
		return nil, fmt.Errorf("(%s) error loading node credentials from storage: %w", op, err)
	}

	switch {
	case opts.WithStorageWrapper == nil && nodeCreds.WrappingKeyId != "":
		return nil, fmt.Errorf("(%s) node credentials has encrypted parts with wrapper key id %q but wrapper not provided", op, nodeCreds.WrappingKeyId)
	case nodeCreds.WrappingKeyId != "":
		// Note: not checking the wrapper key IDs against each other because if
		// using something like a PooledWrapper then the current encryping ID
		// may not match, or if the wrapper performs its own internal key
		// selection.
		blobInfo := new(wrapping.BlobInfo)
		if err := proto.Unmarshal(nodeCreds.CertificatePrivateKeyPkcs8, blobInfo); err != nil {
			return nil, fmt.Errorf("(%s) error unmarshaling certificate private key blob info: %w", op, err)
		}
		pt, err := opts.WithStorageWrapper.Decrypt(
			ctx,
			blobInfo,
			wrapping.WithAad(nodeCreds.CertificatePublicKeyPkix),
		)
		if err != nil {
			return nil, fmt.Errorf("(%s) error decrypting certificate private key: %w", op, err)
		}
		nodeCreds.CertificatePrivateKeyPkcs8 = pt

		if len(nodeCreds.EncryptionPrivateKeyBytes) != 0 {
			blobInfo = new(wrapping.BlobInfo)
			if err := proto.Unmarshal(nodeCreds.EncryptionPrivateKeyBytes, blobInfo); err != nil {
				return nil, fmt.Errorf("(%s) error unmarshaling encryption private key blob info: %w", op, err)
			}
			pt, err = opts.WithStorageWrapper.Decrypt(
				ctx,
				blobInfo,
				wrapping.WithAad(nodeCreds.CertificatePublicKeyPkix),
			)
			if err != nil {
				return nil, fmt.Errorf("(%s) error decrypting encryption private key: %w", op, err)
			}
			nodeCreds.EncryptionPrivateKeyBytes = pt
		}

		if len(nodeCreds.RegistrationNonce) != 0 {
			blobInfo = new(wrapping.BlobInfo)
			if err := proto.Unmarshal(nodeCreds.RegistrationNonce, blobInfo); err != nil {
				return nil, fmt.Errorf("(%s) error unmarshaling registration nonce blob info: %w", op, err)
			}
			pt, err := opts.WithStorageWrapper.Decrypt(
				ctx,
				blobInfo,
				wrapping.WithAad(nodeCreds.CertificatePublicKeyPkix),
			)
			if err != nil {
				return nil, fmt.Errorf("(%s) error decrypting registration nonce: %w", op, err)
			}
			nodeCreds.RegistrationNonce = pt
		}
		if len(nodeCreds.EncryptedRegistrationChallenge) != 0 {
			blobInfo = new(wrapping.BlobInfo)
			if err := proto.Unmarshal(nodeCreds.EncryptedRegistrationChallenge, blobInfo); err != nil {
				return nil, fmt.Errorf("(%s) error unmarshaling registration nonce blob info: %w", op, err)
			}
			pt, err := opts.WithStorageWrapper.Decrypt(
				ctx,
				blobInfo,
				wrapping.WithAad(nodeCreds.CertificatePublicKeyPkix),
			)
			if err != nil {
				return nil, fmt.Errorf("(%s) error decrypting registration nonce: %w", op, err)
			}
			if nodeCreds.RegistrationChallenge == nil {
				nodeCreds.RegistrationChallenge = &RegistrationChallenge{}
			}
			if err := proto.Unmarshal(pt, nodeCreds.RegistrationChallenge); err != nil {
				return nil, fmt.Errorf("(%s) error unmarshaling registration challenge: %w", op, err)
			}
			nodeCreds.EncryptedRegistrationChallenge = nil
		}
		if len(nodeCreds.EncryptedMlkemParameters) != 0 {
			blobInfo = new(wrapping.BlobInfo)
			if err := proto.Unmarshal(nodeCreds.EncryptedMlkemParameters, blobInfo); err != nil {
				return nil, fmt.Errorf("(%s) error unmarshaling mlkem parameters blob info: %w", op, err)
			}
			pt, err := opts.WithStorageWrapper.Decrypt(
				ctx,
				blobInfo,
				wrapping.WithAad(nodeCreds.CertificatePublicKeyPkix),
			)
			if err != nil {
				return nil, fmt.Errorf("(%s) error decrypting mlkem parameters: %w", op, err)
			}
			if nodeCreds.MlkemParameters == nil {
				nodeCreds.MlkemParameters = &MLKEMParameters{}
			}
			if err := proto.Unmarshal(pt, nodeCreds.MlkemParameters); err != nil {
				return nil, fmt.Errorf("(%s) error unmarshaling mlkem parameters: %w", op, err)
			}
			nodeCreds.EncryptedMlkemParameters = nil
		}

		nodeCreds.WrappingKeyId = ""
	}

	return nodeCreds, nil
}

func (n *NodeCredentials) CurrentSharedEncryptionKey() (nodeenrollment.EncryptionKeyMaterial, error) {
	const op = "nodeenrollment.types.(NodeCredentials).CurrentSharedEncryptionKey"
	if nodeenrollment.IsNil(n) {
		return nodeenrollment.EncryptionKeyMaterial{}, fmt.Errorf("(%s) node credentials is empty", op)
	}

	var out []byte
	var err error

	switch {
	case n.EncryptionPrivateKeyType == KEYTYPE_MLKEM1024:
		if n.MlkemParameters == nil {
			return nodeenrollment.EncryptionKeyMaterial{}, fmt.Errorf("(%s) mlkem key type specified but mlkem parameters are nil", op)
		}
		if len(n.MlkemParameters.SharedKey) == 0 {
			return nodeenrollment.EncryptionKeyMaterial{}, fmt.Errorf("(%s) mlkem key type specified but shared key is empty", op)
		}
		out = n.MlkemParameters.SharedKey
	case n.EncryptionPrivateKeyType == KEYTYPE_X25519:
		out, err = DeriveSharedX25519EncryptionKey(n.EncryptionPrivateKeyBytes, n.EncryptionPrivateKeyType, n.ServerEncryptionPublicKeyBytes, n.ServerEncryptionPublicKeyType)
		if err != nil {
			return nodeenrollment.EncryptionKeyMaterial{}, fmt.Errorf("(%s) error deriving encryption key: %w", op, err)
		}
	default:
		return nodeenrollment.EncryptionKeyMaterial{}, fmt.Errorf("(%s) unsupported key type: %d", op, n.EncryptionPrivateKeyType)
	}

	keyId, err := nodeenrollment.KeyIdFromPkix(n.CertificatePublicKeyPkix)
	if err != nil {
		return nodeenrollment.EncryptionKeyMaterial{}, fmt.Errorf("(%s) error deriving key id: %w", op, err)
	}

	return nodeenrollment.EncryptionKeyMaterial{
		KeyId:     keyId,
		KeyType:   uint(n.EncryptionPrivateKeyType),
		SharedKey: out,
	}, nil
}

func (n *NodeCredentials) PreviousSharedEncryptionKey() (nodeenrollment.EncryptionKeyMaterial, error) {
	const op = "nodeenrollment.types.(NodeCredentials).PreviousSharedEncryptionKey"

	if nodeenrollment.IsNil(n) {
		return nodeenrollment.EncryptionKeyMaterial{}, fmt.Errorf("(%s) node credentials is empty", op)
	}

	previousKey := n.PreviousEncryptionKey
	if previousKey == nil {
		return nodeenrollment.EncryptionKeyMaterial{}, fmt.Errorf("(%s) previous key is empty", op)
	}

	var out []byte
	var err error

	switch {
	case previousKey.PrivateKeyType == KEYTYPE_X25519:
		out, err = DeriveSharedX25519EncryptionKey(previousKey.PrivateKeyBytes, previousKey.PrivateKeyType, previousKey.PublicKeyBytes, previousKey.PublicKeyType)
		if err != nil {
			return nodeenrollment.EncryptionKeyMaterial{}, fmt.Errorf("(%s) error deriving previous encryption key: %w", op, err)
		}
	case previousKey.PrivateKeyType == KEYTYPE_MLKEM1024:
		if previousKey.MlkemParameters == nil {
			return nodeenrollment.EncryptionKeyMaterial{}, fmt.Errorf("(%s) previous key has mlkem key type but mlkem parameters are nil", op)
		}
		if len(previousKey.MlkemParameters.SharedKey) == 0 {
			return nodeenrollment.EncryptionKeyMaterial{}, fmt.Errorf("(%s) previous key has mlkem key type but shared key is empty", op)
		}
		out = previousKey.MlkemParameters.SharedKey
	default:
		return nodeenrollment.EncryptionKeyMaterial{}, fmt.Errorf("(%s) unsupported previous key type: %d", op, previousKey.PrivateKeyType)
	}

	return nodeenrollment.EncryptionKeyMaterial{
		KeyId:     previousKey.KeyId,
		KeyType:   uint(previousKey.PrivateKeyType),
		SharedKey: out,
	}, nil
}

// X25519EncryptionKey uses the NodeCredentials values to produce a shared
// encryption key via X25519.
func (n *NodeCredentials) X25519EncryptionKey() (string, []byte, error) {
	const op = "nodeenrollment.types.(NodeCredentials).X25519EncryptionKey"
	if nodeenrollment.IsNil(n) {
		return "", nil, fmt.Errorf("(%s) node credentials is empty", op)
	}

	out, err := X25519EncryptionKey(n.EncryptionPrivateKeyBytes, n.EncryptionPrivateKeyType, n.ServerEncryptionPublicKeyBytes, n.ServerEncryptionPublicKeyType)
	if err != nil {
		return "", nil, fmt.Errorf("(%s) error deriving encryption key: %w", op, err)
	}

	keyId, err := nodeenrollment.KeyIdFromPkix(n.CertificatePublicKeyPkix)
	if err != nil {
		return "", nil, fmt.Errorf("(%s) error deriving key id: %w", op, err)
	}

	return keyId, out, nil
}

// PreviousX25519EncryptionKey satisfies the X25519Producer and will produce a shared
// encryption key via X25519 if previous key data is present.
func (n *NodeCredentials) PreviousX25519EncryptionKey() (string, []byte, error) {
	const op = "nodeenrollment.types.(NodeCredentials).PreviousX25519EncryptionKey"

	if nodeenrollment.IsNil(n) {
		return "", nil, fmt.Errorf("(%s) node credentials is empty", op)
	}

	previousKey := n.PreviousEncryptionKey
	if previousKey == nil {
		return "", nil, fmt.Errorf("(%s) previous key is empty", op)
	}

	out, err := X25519EncryptionKey(previousKey.PrivateKeyBytes, previousKey.PrivateKeyType, previousKey.PublicKeyBytes, previousKey.PublicKeyType)
	if err != nil {
		return "", nil, fmt.Errorf("(%s) error deriving previous encryption key: %w", op, err)
	}

	return previousKey.KeyId, out, nil
}

// NewNodeCredentials creates a new node credentials object and populates it
// with suitable parameters for presenting for registration.
//
// Once registration succeeds, the node credentials stored here can be used to
// decrypt the incoming bundle with the server's view of the node credentials,
// which can then be merged; this happens in a different function.
//
// Supported options: WithRandomReader, WithStorageWrapper (passed through to
// NodeCredentials.Store), WithSkipStorage, WithActivationToken,
// WithEncryptionPrivateKeyType
func NewNodeCredentials(
	ctx context.Context,
	storage nodeenrollment.Storage,
	opt ...nodeenrollment.Option,
) (*NodeCredentials, error) {
	const op = "nodeenrollment.types.NewNodeCredentials"

	if nodeenrollment.IsNil(storage) {
		return nil, fmt.Errorf("(%s) storage is nil", op)
	}

	n := new(NodeCredentials)

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	var (
		certPubKey  ed25519.PublicKey
		certPrivKey ed25519.PrivateKey
	)

	// Create challenge
	n.RegistrationChallenge = new(RegistrationChallenge)
	n.RegistrationChallenge.Challenge = make([]byte, nodeenrollment.NonceSize)
	num, err := opts.WithRandomReader.Read(n.RegistrationChallenge.Challenge)
	switch {
	case err != nil:
		return nil, fmt.Errorf("(%s) error generating challenge: %w", op, err)
	case num != nodeenrollment.NonceSize:
		return nil, fmt.Errorf("(%s) read incorrect number of bytes for challenge, wanted %d, got %d", op, nodeenrollment.NonceSize, num)
	}

	// Create certificate keypair
	{
		certPubKey, certPrivKey, err = ed25519.GenerateKey(opts.WithRandomReader)
		if err != nil {
			return nil, fmt.Errorf("(%s) error generating certificate keypair: %w", op, err)
		}

		n.CertificatePrivateKeyPkcs8, err = x509.MarshalPKCS8PrivateKey(certPrivKey)
		if err != nil {
			return nil, fmt.Errorf("(%s) error marshaling certificate private key: %w", op, err)
		}
		n.CertificatePrivateKeyType = KEYTYPE_ED25519

		n.CertificatePublicKeyPkix, _, err = nodeenrollment.SubjectKeyInfoAndKeyIdFromPubKey(certPubKey)
		if err != nil {
			return nil, fmt.Errorf("(%s) error fetching public key id: %w", op, err)
		}
	}

	// Create node encryption keys
	{
		switch KEYTYPE(opts.WithEncryptionPrivateKeyType) {
		case KEYTYPE_MLKEM1024, KEYTYPE_UNSPECIFIED:
			decapsulationKey, err := mlkem.GenerateKey1024()
			if err != nil {
				return nil, fmt.Errorf("(%s) error generating mlkem decapsulation key: %w", op, err)
			}
			n.MlkemParameters = &MLKEMParameters{
				DecapsulationKey: decapsulationKey.Bytes(),
			}
			n.EncryptionPrivateKeyType = KEYTYPE_MLKEM1024
		case KEYTYPE_X25519:
			n.EncryptionPrivateKeyBytes = make([]byte, curve25519.ScalarSize)
			num, err := opts.WithRandomReader.Read(n.EncryptionPrivateKeyBytes)
			switch {
			case err != nil:
				return nil, fmt.Errorf("(%s) error reading random bytes to generate node encryption key: %w", op, err)
			case num != curve25519.ScalarSize:
				return nil, fmt.Errorf("(%s) wrong number of random bytes read when generating node encryption key, expected %d but got %d", op, curve25519.ScalarSize, num)
			}
			n.EncryptionPrivateKeyType = KEYTYPE_X25519
		default:
			return nil, fmt.Errorf("(%s) unsupported encryption private key type: %v", op, opts.WithEncryptionPrivateKeyType)
		}
	}

	n.Id = string(nodeenrollment.CurrentId)
	if !opts.WithSkipStorage {
		if err := n.Store(ctx, storage, opt...); err != nil {
			return nil, fmt.Errorf("(%s) failed to store generated node creds: %w", op, err)
		}
	}

	return n, nil
}

// SetPreviousEncryptionKey will set this NodeCredential's PreviousEncryptionKey field
// using the passed NodeCredentials
func (n *NodeCredentials) SetPreviousEncryptionKey(oldNodeCredentials *NodeCredentials) error {
	const op = "nodeenrollment.types.(NodeCredentials).SetPreviousEncryptionKey"
	if oldNodeCredentials == nil {
		return fmt.Errorf("(%s) empty prior credentials passed in", op)
	}

	keyId, err := nodeenrollment.KeyIdFromPkix(oldNodeCredentials.CertificatePublicKeyPkix)
	if err != nil {
		return fmt.Errorf("(%s) error deriving key id: %w", op, err)
	}
	previousEncryptionKey := &EncryptionKey{
		KeyId:          keyId,
		PrivateKeyType: oldNodeCredentials.EncryptionPrivateKeyType,
		PublicKeyType:  oldNodeCredentials.ServerEncryptionPublicKeyType,
	}
	if len(oldNodeCredentials.EncryptionPrivateKeyBytes) > 0 {
		previousEncryptionKey.PrivateKeyBytes = make([]byte, len(oldNodeCredentials.EncryptionPrivateKeyBytes))
		copy(previousEncryptionKey.PrivateKeyBytes, oldNodeCredentials.EncryptionPrivateKeyBytes)
	}
	if len(oldNodeCredentials.ServerEncryptionPublicKeyBytes) > 0 {
		previousEncryptionKey.PublicKeyBytes = make([]byte, len(oldNodeCredentials.ServerEncryptionPublicKeyBytes))
		copy(previousEncryptionKey.PublicKeyBytes, oldNodeCredentials.ServerEncryptionPublicKeyBytes)
	}
	if oldNodeCredentials.MlkemParameters != nil {
		previousEncryptionKey.MlkemParameters = new(MLKEMParameters)
		if len(oldNodeCredentials.MlkemParameters.Ciphertext) > 0 {
			previousEncryptionKey.MlkemParameters.Ciphertext = make([]byte, len(oldNodeCredentials.MlkemParameters.Ciphertext))
			copy(previousEncryptionKey.MlkemParameters.Ciphertext, oldNodeCredentials.MlkemParameters.Ciphertext)
		}
		if len(oldNodeCredentials.MlkemParameters.SharedKey) > 0 {
			previousEncryptionKey.MlkemParameters.SharedKey = make([]byte, len(oldNodeCredentials.MlkemParameters.SharedKey))
			copy(previousEncryptionKey.MlkemParameters.SharedKey, oldNodeCredentials.MlkemParameters.SharedKey)
		}
	}
	n.PreviousEncryptionKey = previousEncryptionKey

	return nil
}

// CreateFetchNodeCredentialsRequest creates and returns a fetch request based
// on the current node creds
//
// Supported options: WithRandomReader, WithActivationToken (used in place of
// the node's nonce value if provided, for the server-led flow; note that this
// should be the full string token, it will be decoded by this function),
// WithRegistrationWrapper/WithWrappingRegistrationFlowApplicationSpecificParams,
// WithRegistrationChallenge, WithEncryptionPrivateKeyType
func (n *NodeCredentials) CreateFetchNodeCredentialsRequest(
	ctx context.Context,
	storage nodeenrollment.Storage,
	opt ...nodeenrollment.Option,
) (*FetchNodeCredentialsRequest, error) {
	const op = "nodeenrollment.types.(NodeCredentials).CreateFetchNodeCredentialsRequest"

	switch {
	case nodeenrollment.IsNil(n):
		return nil, fmt.Errorf("(%s) node credentials is nil", op)
	case len(n.CertificatePrivateKeyPkcs8) == 0:
		return nil, fmt.Errorf("(%s) node credentials pkcs8 private key is empty", op)
	case len(n.CertificatePublicKeyPkix) == 0:
		return nil, fmt.Errorf("(%s) node credentials pkix public key is empty", op)
	case n.RegistrationChallenge == nil && len(n.RegistrationNonce) == 0:
		return nil, fmt.Errorf("(%s) node credentials registration challenge is missing", op)
	case n.RegistrationChallenge != nil && len(n.RegistrationChallenge.Challenge) == 0:
		return nil, fmt.Errorf("(%s) node credentials registration challenge is empty", op)
	case len(n.EncryptionPrivateKeyBytes) == 0 && n.MlkemParameters == nil:
		return nil, fmt.Errorf("(%s) node credentials encryption private key is empty", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(n.CertificatePrivateKeyPkcs8)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing private key: %w", op, err)
	}

	now := time.Now()
	reqInfo := &FetchNodeCredentialsInfo{
		CertificatePublicKeyPkix:         n.CertificatePublicKeyPkix,
		CertificatePublicKeyType:         n.CertificatePrivateKeyType,
		PreviousCertificatePublicKeyPkix: n.PreviousCertificatePublicKeyPkix,
		EncryptionPublicKeyType:          n.EncryptionPrivateKeyType,
		NotBefore:                        timestamppb.New(now),
		NotAfter:                         timestamppb.New(now.Add(nodeenrollment.DefaultFetchCredentialsLifetime)),
	}
	if n.RegistrationChallenge != nil && !opts.WithoutRegistrationChallenge {
		reqInfo.RegistrationChallenge = n.RegistrationChallenge
	} else if n.RegistrationChallenge == nil && len(n.RegistrationNonce) > 0 {
		reqInfo.Nonce = n.RegistrationNonce
	}

	switch n.EncryptionPrivateKeyType {
	case KEYTYPE_MLKEM1024:
		// If we're in a server flow we aren't providing the encapsulation key
		if opts.WithActivationToken != "" {
			break
		}
		if n.MlkemParameters == nil {
			return nil, fmt.Errorf("(%s) node credentials has mlkem encryption key type but mlkem parameters are nil", op)
		}
		if len(n.MlkemParameters.Ciphertext) != 0 && len(n.MlkemParameters.SharedKey) != 0 {
			// This isn't the first fetch request, and we don't want to send the
			// encapsulation key again as a new encapsulation would change the
			// shared key. We include the ciphertext to allow the server to optionally
			// perform consistency checks across requests.
			reqInfo.MlkemParameters = &MLKEMParameters{
				Ciphertext: n.MlkemParameters.Ciphertext,
			}
			break
		}
		if len(n.MlkemParameters.DecapsulationKey) == 0 {
			return nil, fmt.Errorf("(%s) node credentials has mlkem encryption key type but mlkem private key bytes are empty", op)
		}
		decapsulationKey, err := mlkem.NewDecapsulationKey1024(n.MlkemParameters.DecapsulationKey)
		if err != nil {
			return nil, fmt.Errorf("(%s) error reading mlkem decapsulation key: %w", op, err)
		}
		reqInfo.MlkemParameters = &MLKEMParameters{
			EncapsulationKey: decapsulationKey.EncapsulationKey().Bytes(),
		}
	case KEYTYPE_X25519:
		encryptionPrivateKey, err := ecdh.X25519().NewPrivateKey(n.EncryptionPrivateKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("(%s) error reading node private encryption key: %w", op, err)
		}
		reqInfo.EncryptionPublicKeyBytes = encryptionPrivateKey.PublicKey().Bytes()
	default:
		return nil, fmt.Errorf("(%s) unknown encryption key type: %s", op, n.EncryptionPrivateKeyType.String())
	}

	switch {
	case !nodeenrollment.IsNil(opts.WithRegistrationWrapper):
		// Create an encrypted registration request
		regInfo := &WrappingRegistrationFlowInfo{
			CertificatePublicKeyPkix:  n.CertificatePublicKeyPkix,
			Nonce:                     n.RegistrationNonce,
			ApplicationSpecificParams: opts.WithWrappingRegistrationFlowApplicationSpecificParams,
		}
		regInfoBytes, err := proto.Marshal(regInfo)
		if err != nil {
			return nil, fmt.Errorf("(%s) error marshaling wrapping flow registration info: %w", op, err)
		}
		blobInfo, err := opts.WithRegistrationWrapper.Encrypt(ctx, regInfoBytes)
		if err != nil {
			return nil, fmt.Errorf("(%s) error encrypting wrapping flow registration info: %w", op, err)
		}
		encryptedRegInfo, err := proto.Marshal(blobInfo)
		if err != nil {
			return nil, fmt.Errorf("(%s) error marshaling encrypted wrapping flow registration info: %w", op, err)
		}
		reqInfo.WrappedRegistrationInfo = encryptedRegInfo

	case opts.WithActivationToken != "":
		reqInfo.Nonce = nil
		reqInfo.RegistrationChallenge = nil

		nonce, err := base58.FastBase58Decoding(strings.TrimPrefix(opts.WithActivationToken, nodeenrollment.ServerLedActivationTokenPrefix))
		if err != nil {
			return nil, fmt.Errorf("(%s) error base58-decoding activation token: %w", op, err)
		}
		tokenNonce := new(ServerLedActivationTokenNonce)
		if err := proto.Unmarshal(nonce, tokenNonce); err != nil {
			if strings.Contains(err.Error(), "cannot parse invalid wire-format data") {
				return nil, fmt.Errorf("(%s) invalid registration nonce: %w", op, err)
			}
			return nil, fmt.Errorf("(%s) error unmarshaling server-led activation token: %w", op, err)
		}
		// If this is not populated, it's the old version, and use old behavior
		if len(tokenNonce.ActivationTokenId) == 0 {
			switch {
			case len(tokenNonce.Nonce) == 0:
				return nil, fmt.Errorf("(%s) nil server-led activation token nonce", op)
			case len(tokenNonce.HmacKeyBytes) == 0:
				return nil, fmt.Errorf("(%s) nil server-led activation token hmac key bytes", op)
			}
			if n.EncryptionPrivateKeyType != KEYTYPE_X25519 {
				return nil, fmt.Errorf("(%s) server-led activation token without activation token ID is only supported with X25519 node encryption keys", op)
			}
			reqInfo.Nonce = nonce
		} else {
			n.ServerEncryptionPublicKeyType = tokenNonce.ServerEncryptionPublicKeyType
			switch n.ServerEncryptionPublicKeyType {
			case KEYTYPE_X25519:
				n.ServerEncryptionPublicKeyBytes = tokenNonce.ServerEncryptionPublicKeyBytes
				if len(n.ServerEncryptionPublicKeyBytes) == 0 {
					return nil, fmt.Errorf("(%s) server-led activation token includes server encryption key info but node credentials is missing server encryption public key bytes", op)
				}
				if len(n.ServerEncryptionPublicKeyBytes) != curve25519.PointSize {
					return nil, fmt.Errorf("(%s) server-led activation token includes server encryption key info but node credentials has invalid server encryption public key bytes length %d", op, len(n.ServerEncryptionPublicKeyBytes))
				}
			case KEYTYPE_MLKEM1024:
				if n.EncryptionPrivateKeyType != KEYTYPE_MLKEM1024 {
					return nil, fmt.Errorf("(%s) server-led activation token requires mlkem1024 but node credentials encryption key type is %s", op, n.EncryptionPrivateKeyType.String())
				}
				if len(tokenNonce.MlkemEncapsulationKeyBytes) == 0 {
					return nil, fmt.Errorf("(%s) server-led activation token includes mlkem server encryption key type but mlkem encapsulation key bytes are empty", op)
				}
				n.MlkemParameters = &MLKEMParameters{
					EncapsulationKey: tokenNonce.MlkemEncapsulationKeyBytes,
				}
				encapsulationKey, err := mlkem.NewEncapsulationKey1024(n.MlkemParameters.EncapsulationKey)
				if err != nil {
					return nil, fmt.Errorf("(%s) error parsing mlkem encapsulation key from server-led activation token: %w", op, err)
				}
				n.MlkemParameters.SharedKey, n.MlkemParameters.Ciphertext = encapsulationKey.Encapsulate()
				if reqInfo.MlkemParameters == nil {
					reqInfo.MlkemParameters = &MLKEMParameters{}
				}
				reqInfo.MlkemParameters.EncapsulationKey = n.MlkemParameters.EncapsulationKey
				reqInfo.MlkemParameters.Ciphertext = n.MlkemParameters.Ciphertext
			default:
				return nil, fmt.Errorf("(%s) server-led activation token includes unknown server encryption key type %d", op, tokenNonce.ServerEncryptionPublicKeyType)
			}
			reqInfo.ActivationTokenId = tokenNonce.ActivationTokenId
			challenge := new(RegistrationChallenge)
			challenge.Challenge = tokenNonce.Nonce
			reqInfo.EncryptedRegistrationChallenge, err = nodeenrollment.EncryptMessage(
				ctx,
				challenge,
				n,
				opt...,
			)
			if err != nil {
				return nil, fmt.Errorf("(%s) error encrypting registration challenge: %w", op, err)
			}
			// Persist the expected server information so that if there is a
			// reload we aren't relying purely on memory between this call and
			// the fetch, although if this step is skipped due to options we
			// will still be relying on the same object from memory being used.
			if !opts.WithSkipStorage {
				if err := n.Store(ctx, storage, opt...); err != nil {
					return nil, fmt.Errorf("(%s) failed to store node creds with server encryption key info: %w", op, err)
				}
			}
		}
	}

	var req FetchNodeCredentialsRequest
	req.Bundle, err = proto.Marshal(reqInfo)
	if err != nil {
		return nil, fmt.Errorf("(%s) error marshaling fetch node credentials info: %w", op, err)
	}

	sigBytes, err := privKey.(crypto.Signer).Sign(opts.WithRandomReader, req.Bundle, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("(%s) error signing request data message: %w", op, err)
	}
	req.BundleSignature = sigBytes

	return &req, nil
}

// HandleFetchNodeCredentialsResponse parses the response from a server for node
// credentials and attempts to decrypt and merge with the existing
// NodeCredentials, storing the result. It returns the updated value and any
// error and stores the result in storage, unless WithSkipStorage is passed.
//
// Supported options: WithWrapping (passed through to NodeCredentials.Store),
// WithSkipStorage, WithActivationToken (overrides the NodeCredentials' nonce
// when using server-led node authorization)
func (n *NodeCredentials) HandleFetchNodeCredentialsResponse(
	ctx context.Context,
	storage nodeenrollment.Storage,
	input *FetchNodeCredentialsResponse,
	opt ...nodeenrollment.Option,
) (*NodeCredentials, error) {
	const op = "nodeenrollment.types.(NodeCredentials).HandleFetchNodeCredentialsResponse"

	switch {
	case n == nil:
		return nil, fmt.Errorf("(%s) node credentials is nil", op)
	case input == nil:
		return nil, fmt.Errorf("(%s) input is nil", op)
	case len(input.EncryptedNodeCredentials) == 0:
		return nil, fmt.Errorf("(%s) input encrypted node credentials is nil", op)
	case input.ServerEncryptionPublicKeyType == KEYTYPE_X25519 && len(input.ServerEncryptionPublicKeyBytes) == 0:
		return nil, fmt.Errorf("(%s) server encryption public key bytes is nil", op)
	case input.ServerEncryptionPublicKeyType == KEYTYPE_MLKEM1024 && len(input.MlkemCiphertext) == 0:
		return nil, fmt.Errorf("(%s) server encryption key type is mlkem1024 but mlkem ciphertext is nil", op)
	case input.ServerEncryptionPublicKeyType == KEYTYPE_MLKEM1024 && n.MlkemParameters == nil:
		return nil, fmt.Errorf("(%s) server encryption key type is mlkem1024 but mlkem parameters are nil", op)
	case input.ServerEncryptionPublicKeyType != KEYTYPE_X25519 && input.ServerEncryptionPublicKeyType != KEYTYPE_MLKEM1024:
		return nil, fmt.Errorf("(%s) server encryption public key type is unknown", op)
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) nil storage", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	// If it's been set already by CreateFetchNodeCredentialsRequest (in the new
	// protocol), don't overwrite it, but if not then set it from the input
	// (legacy). Node-led will always be missing this info the first time
	// credentials are fetched.
	switch input.ServerEncryptionPublicKeyType {
	case KEYTYPE_X25519:
		if len(n.ServerEncryptionPublicKeyBytes) == 0 {
			n.ServerEncryptionPublicKeyBytes = input.ServerEncryptionPublicKeyBytes
			n.ServerEncryptionPublicKeyType = input.ServerEncryptionPublicKeyType
		} else if subtle.ConstantTimeCompare(n.ServerEncryptionPublicKeyBytes, input.ServerEncryptionPublicKeyBytes) == 0 {
			return nil, fmt.Errorf("(%s) server encryption public key in response does not match expected value", op)
		}
	case KEYTYPE_MLKEM1024:
		if len(n.MlkemParameters.Ciphertext) != 0 {
			// Verify it hasn't changed
			if subtle.ConstantTimeCompare(n.MlkemParameters.Ciphertext, input.MlkemCiphertext) == 0 {
				return nil, fmt.Errorf("(%s) server mlkem ciphertext in response does not match expected value", op)
			}
			// Verify we have the shared key already calculated
			if len(n.MlkemParameters.SharedKey) == 0 {
				return nil, fmt.Errorf("(%s) node credentials has mlkem encryption key type and ciphertext but mlkem parameters shared key is empty", op)
			}
		} else {
			// This is the first fetch, derive the key from the ciphertext
			if len(n.MlkemParameters.DecapsulationKey) == 0 {
				return nil, fmt.Errorf("(%s) node credentials has mlkem encryption key type but mlkem private key bytes are empty", op)
			}
			if len(input.MlkemCiphertext) == 0 {
				return nil, fmt.Errorf("(%s) server mlkem ciphertext in response is empty", op)
			}
			decapsulationKey, err := mlkem.NewDecapsulationKey1024(n.MlkemParameters.DecapsulationKey)
			if err != nil {
				return nil, fmt.Errorf("(%s) error reading mlkem decapsulation key: %w", op, err)
			}
			n.MlkemParameters.SharedKey, err = decapsulationKey.Decapsulate(input.MlkemCiphertext)
			if err != nil {
				return nil, fmt.Errorf("(%s) error decapsulating mlkem shared key: %w", op, err)
			}
			n.MlkemParameters.Ciphertext = input.MlkemCiphertext
			n.MlkemParameters.DecapsulationKey = nil
		}
	default:
		return nil, fmt.Errorf("(%s) server encryption public key type in response is unknown", op)
	}

	newNodeCreds := new(NodeCredentials)
	if err := nodeenrollment.DecryptMessage(
		ctx,
		input.EncryptedNodeCredentials,
		n,
		newNodeCreds,
		opt...,
	); err != nil {
		return nil, fmt.Errorf("(%s) error decrypting server message: %w", op, err)
	}

	// Validate the challenge. If server-led validation, the challenge is
	// generated by the server and we have no expectation to validate against,
	// but if not server-led then we should have a challenge in our creds that
	// we can validate against.
	if len(opts.WithActivationToken) == 0 {
		if n.RegistrationChallenge == nil {
			switch {
			case len(n.RegistrationNonce) == 0:
				return nil, fmt.Errorf("(%s) expected registration challenge or nonce in node credentials but both were nil", op)
			case len(newNodeCreds.RegistrationNonce) == 0:
				return nil, fmt.Errorf("(%s) expected registration nonce in server response but it was nil", op)
			case subtle.ConstantTimeCompare(n.RegistrationNonce, newNodeCreds.RegistrationNonce) == 0:
				return nil, fmt.Errorf("(%s) server message decrypted successfully but nonce does not match", op)
			}
		} else {
			switch {
			case newNodeCreds.EncryptedRegistrationChallenge == nil:
				return nil, fmt.Errorf("(%s) expected encrypted registration challenge in server response but it was nil", op)
			case len(n.RegistrationChallenge.Challenge) == 0:
				return nil, fmt.Errorf("(%s) expected registration challenge challenge value in node credentials but it was empty", op)
			}
			registrationChallenge := new(RegistrationChallenge)
			if err := nodeenrollment.DecryptMessage(
				ctx,
				newNodeCreds.EncryptedRegistrationChallenge,
				n,
				registrationChallenge,
				opt...,
			); err != nil {
				return nil, fmt.Errorf("(%s) error decrypting registration challenge: %w", op, err)
			}
			if len(registrationChallenge.Challenge) == 0 {
				return nil, fmt.Errorf("(%s) decrypted registration challenge is empty", op)
			}
			if subtle.ConstantTimeCompare(n.RegistrationChallenge.Challenge, registrationChallenge.Challenge) == 0 {
				return nil, fmt.Errorf("(%s) server message decrypted successfully but challenge does not match", op)
			}
		}
	}
	n.RegistrationNonce = nil
	n.RegistrationChallenge = nil

	// Now copy values over
	n.CertificateBundles = newNodeCreds.CertificateBundles

	n.Id = string(nodeenrollment.CurrentId)
	if !opts.WithSkipStorage {
		if err := n.Store(ctx, storage, opt...); err != nil {
			return nil, fmt.Errorf("(%s) failed to store updated node creds: %w", op, err)
		}
	}

	return n, nil
}
