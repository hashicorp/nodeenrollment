package nodetypes

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	nodee "github.com/hashicorp/nodeenrollment"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
)

var _ nodee.X25519Producer = (*NodeCredentials)(nil)

// Store stores node credentials to server storage, wrapping values along the
// way if given a wrapper
//
// Supported options: WithWrapper
func (n *NodeCredentials) Store(ctx context.Context, storage nodee.Storage, opt ...nodee.Option) error {
	const op = "nodee.nodetypes.(NodeCredentials).Store"

	switch n.Id {
	case "":
		return fmt.Errorf("(%s) credentials is missing id", op)
	case nodee.CurrentId, nodee.NextId:
	default:
		return fmt.Errorf("(%s) invalid node credentials id", op)
	}

	opts, err := nodee.GetOpts(opt...)
	if err != nil {
		return fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	credsToStore := n
	if opts.WithWrapper != nil {
		keyId, err := opts.WithWrapper.KeyId(ctx)
		if err != nil {
			return fmt.Errorf("(%s) error reading wrapper key id: %w", op, err)
		}
		n.WrappingKeyId = keyId
		credsToStore = proto.Clone(n).(*NodeCredentials)

		blobInfo, err := opts.WithWrapper.Encrypt(
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

		blobInfo, err = opts.WithWrapper.Encrypt(
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

		if len(credsToStore.RegistrationNonce) != 0 {
			blobInfo, err = opts.WithWrapper.Encrypt(
				ctx,
				[]byte(credsToStore.RegistrationNonce),
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
	}

	if err := storage.Store(ctx, credsToStore); err != nil {
		return fmt.Errorf("(%s) error storing node credentials: %w", op, err)
	}

	return nil
}

// LoadNoadCredentials loads the node credentials from storage, unwrapping
// encrypted values if needed.
//
// Supported options: WithWrapper
func LoadNodeCredentials(ctx context.Context, storage nodee.Storage, id string, opt ...nodee.Option) (*NodeCredentials, error) {
	const op = "nodee.nodetypes.LoadNodeCredentials"

	switch id {
	case "":
		return nil, fmt.Errorf("(%s) credentials is missing id", op)
	case nodee.CurrentId, nodee.NextId:
	default:
		return nil, fmt.Errorf("(%s) invalid node credentials id", op)
	}

	opts, err := nodee.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	nodeCreds := &NodeCredentials{
		Id: id,
	}
	if err := storage.Load(ctx, nodeCreds); err != nil {
		return nil, fmt.Errorf("(%s) error loading node credentials from storage: %w", op, err)
	}

	if nodeCreds.WrappingKeyId != "" {
		if opts.WithWrapper == nil {
			return nil, fmt.Errorf("(%s) node credentials has encrypted parts with wrapper key id %q but wrapper not provided", op, nodeCreds.WrappingKeyId)
		}
		// Note: not checking the wrapper key IDs against each other because if
		// using something like a PooledWrapper then the current encryping ID
		// may not match, or if the wrapper performs its own internal key
		// selection.
		blobInfo := new(wrapping.BlobInfo)
		if err := proto.Unmarshal(nodeCreds.CertificatePrivateKeyPkcs8, blobInfo); err != nil {
			return nil, fmt.Errorf("(%s) error unmarshaling certificate private key blob info: %w", op, err)
		}
		pt, err := opts.WithWrapper.Decrypt(
			ctx,
			blobInfo,
			wrapping.WithAad(nodeCreds.CertificatePublicKeyPkix),
		)
		if err != nil {
			return nil, fmt.Errorf("(%s) error decrypting certificate private key: %w", op, err)
		}
		nodeCreds.CertificatePrivateKeyPkcs8 = pt

		blobInfo = new(wrapping.BlobInfo)
		if err := proto.Unmarshal(nodeCreds.EncryptionPrivateKeyBytes, blobInfo); err != nil {
			return nil, fmt.Errorf("(%s) error unmarshaling encryption private key blob info: %w", op, err)
		}
		pt, err = opts.WithWrapper.Decrypt(
			ctx,
			blobInfo,
			wrapping.WithAad(nodeCreds.CertificatePublicKeyPkix),
		)
		if err != nil {
			return nil, fmt.Errorf("(%s) error decrypting encryption private key: %w", op, err)
		}
		nodeCreds.EncryptionPrivateKeyBytes = pt

		if len(nodeCreds.RegistrationNonce) != 0 {
			blobInfo = new(wrapping.BlobInfo)
			if err := proto.Unmarshal(nodeCreds.RegistrationNonce, blobInfo); err != nil {
				return nil, fmt.Errorf("(%s) error unmarshaling registration nonce blob info: %w", op, err)
			}
			pt, err := opts.WithWrapper.Decrypt(
				ctx,
				blobInfo,
				wrapping.WithAad(nodeCreds.CertificatePublicKeyPkix),
			)
			if err != nil {
				return nil, fmt.Errorf("(%s) error decrypting registration nonce: %w", op, err)
			}
			nodeCreds.RegistrationNonce = pt
		}

		nodeCreds.WrappingKeyId = ""
	}

	return nodeCreds, nil
}

// GenerateRegistrationParameters creates and stores initial
// NodeCredentials with suitable options for presenting for noderegistration.
// The output is a string with the key ID to display to a user for verification.
//
// Once registration succeeds, the node credentials stored here can be used to
// decrypt the incoming bundle with the server's view of the node credentials,
// which can then be merged.
//
// Supported options: WithRandomReader, WithWrapper (passed through to
// NodeCredentials.Store)
func (n *NodeCredentials) GenerateRegistrationParameters(
	ctx context.Context,
	storage nodee.Storage,
	opt ...nodee.Option,
) error {
	const op = "nodee.nodetypes.GenerateRegistrationParameters"

	switch {
	case len(n.CertificatePrivateKeyPkcs8) != 0,
		len(n.EncryptionPrivateKeyBytes) != 0,
		len(n.RegistrationNonce) != 0,
		n.Id != "":
		return fmt.Errorf("(%s) this function cannot be called on existing node credentials", op)
	}

	opts, err := nodee.GetOpts(opt...)
	if err != nil {
		return fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	var (
		certPubKey  ed25519.PublicKey
		certPrivKey ed25519.PrivateKey
	)

	n.RegistrationNonce = make([]byte, nodee.NonceSize)
	num, err := opts.WithRandomReader.Read(n.RegistrationNonce)
	switch {
	case err != nil:
		return fmt.Errorf("(%s) error generating nonce: %w", op, err)
	case num != nodee.NonceSize:
		return fmt.Errorf("(%s) read incorrect number of bytes for nonce, wanted %d, got %d", op, nodee.NonceSize, num)
	}

	// Create certificate keypair
	{
		certPubKey, certPrivKey, err = ed25519.GenerateKey(opts.WithRandomReader)
		if err != nil {
			return fmt.Errorf("(%s) error generating certificate keypair: %w", op, err)
		}

		n.CertificatePrivateKeyPkcs8, err = x509.MarshalPKCS8PrivateKey(certPrivKey)
		if err != nil {
			return fmt.Errorf("(%s) error marshaling certificate private key: %w", op, err)
		}
		n.CertificatePrivateKeyType = KEYTYPE_KEYTYPE_ED25519

		n.CertificatePublicKeyPkix, _, err = nodee.SubjectKeyInfoAndKeyIdFromPubKey(certPubKey)
		if err != nil {
			return fmt.Errorf("(%s) error fetching public key id: %w", op, err)
		}
	}

	// Create node encryption keys
	{
		n.EncryptionPrivateKeyBytes = make([]byte, curve25519.ScalarSize)
		num, err := opts.WithRandomReader.Read(n.EncryptionPrivateKeyBytes)
		switch {
		case err != nil:
			return fmt.Errorf("(%s) error reading random bytes to generate node encryption key: %w", op, err)
		case num != curve25519.ScalarSize:
			return fmt.Errorf("(%s) wrong number of random bytes read when generating node encryption key, expected %d but got %d", op, curve25519.ScalarSize, num)
		}
		n.EncryptionPrivateKeyType = KEYTYPE_KEYTYPE_X25519
	}

	n.Id = nodee.CurrentId
	if err := n.Store(ctx, storage, opt...); err != nil {
		return fmt.Errorf("(%s) failed to store generated node creds: %w", op, err)
	}

	return nil
}

// CreateFetchNodeCredentialsRequest returns the fetch request based on the
// current node creds
func (n *NodeCredentials) CreateFetchNodeCredentialsRequest(ctx context.Context, opt ...nodee.Option) (*FetchNodeCredentialsRequest, error) {
	const op = "nodee.nodetypes.(NodeCredentials).CreateFetchNodeCredentialsRequest"

	opts, err := nodee.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(n.CertificatePrivateKeyPkcs8)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing private key: %w", op, err)
	}

	reqInfo := &FetchNodeCredentialsInfo{
		CertificatePublicKeyPkix: n.CertificatePublicKeyPkix,
		CertificatePublicKeyType: n.CertificatePrivateKeyType,
		Nonce:                    n.RegistrationNonce,
		EncryptionPublicKeyType:  KEYTYPE_KEYTYPE_X25519,
	}
	reqInfo.EncryptionPublicKeyBytes, err = curve25519.X25519(n.EncryptionPrivateKeyBytes, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("(%s) error performing x25519 operation on private key: %w", op, err)
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
// credentials and attempts to decrypt and merge with existing on-disk
// NodeCredentials, storing the result. It returns the updated node credentials
// (same as were stored to disk) to avoid having to do a lookup since the next
// operation is likely to establish a session.
//
// Supported options: WithRandomReader, WithWrapping (passed through to
// NodeCredentials.Store)
func (n *NodeCredentials) HandleFetchNodeCredentialsResponse(
	ctx context.Context,
	storage nodee.Storage,
	input *FetchNodeCredentialsResponse,
	opt ...nodee.Option,
) error {
	const op = "nodee.noderegistration.HandleFetchNodeCredentialsResponse"
	switch {
	case input == nil:
		return fmt.Errorf("(%s) input is nil", op)
	case len(input.EncryptedNodeCredentials) == 0:
		return fmt.Errorf("(%s) input encrypted node credentials is nil", op)
	case len(input.ServerEncryptionPublicKeyBytes) == 0:
		return fmt.Errorf("(%s) server encryption public key bytes is nil", op)
	case input.ServerEncryptionPublicKeyType != KEYTYPE_KEYTYPE_X25519:
		return fmt.Errorf("(%s) server encryption public key is of unknown type", op)
	case storage == nil:
		return fmt.Errorf("(%s) nil storage passed in", op)
	}

	n.ServerEncryptionPublicKeyBytes = input.ServerEncryptionPublicKeyBytes
	n.ServerEncryptionPublicKeyType = input.ServerEncryptionPublicKeyType

	newNodeCreds := new(NodeCredentials)
	if err := nodee.DecryptMessage(
		ctx,
		nodee.KeyIdFromPkix(n.CertificatePublicKeyPkix),
		input.EncryptedNodeCredentials,
		n,
		newNodeCreds,
		opt...,
	); err != nil {
		return fmt.Errorf("(%s) error decrypting server message: %w", op, err)
	}

	// Validate the nonce
	if subtle.ConstantTimeCompare(n.RegistrationNonce, newNodeCreds.RegistrationNonce) == 0 {
		return fmt.Errorf("(%s) server message decrypted successfully but nonce does not match", op)
	}
	n.RegistrationNonce = nil

	// Now copy values over
	n.CertificateBundles = newNodeCreds.CertificateBundles

	n.Id = nodee.CurrentId
	if err := n.Store(ctx, storage, opt...); err != nil {
		return fmt.Errorf("(%s) failed to store updated node creds: %w", op, err)
	}

	return nil
}

// X25519EncryptionKey uses the NodeCredentials values to produce a shared
// encryption key via X25519
func (n *NodeCredentials) X25519EncryptionKey() ([]byte, error) {
	const op = "nodee.nodetypes.(NodeCredentials).X25519EncryptionKey"
	switch {
	case len(n.EncryptionPrivateKeyBytes) == 0:
		return nil, fmt.Errorf("(%s) encryption private key bytes is empty", op)
	case n.EncryptionPrivateKeyType != KEYTYPE_KEYTYPE_X25519:
		return nil, fmt.Errorf("(%s) encryption private key type is not known", op)
	case len(n.ServerEncryptionPublicKeyBytes) == 0:
		return nil, fmt.Errorf("(%s) encryption public key bytes is empty", op)
	case n.ServerEncryptionPublicKeyType != KEYTYPE_KEYTYPE_X25519:
		return nil, fmt.Errorf("(%s) encryption public key type is not known", op)
	}
	return curve25519.X25519(n.EncryptionPrivateKeyBytes, n.ServerEncryptionPublicKeyBytes)
}
