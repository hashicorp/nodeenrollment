// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package registration

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateServerLedActivationToken creates and stores a nonce and returns it;
// this nonce can be used when a node requests to fetch credentials to authorize
// it. The nonce is a serialized protobuf that also contains the creation time.
// The serialized value is HMAC'd before storage.
//
// The returned values are the activation token ID (used as the ID for storage)
// and the token itself.
//
// Supported options: WithRandomReader, WithStorageWrapper (passed through to
// NodeInformation.Store), WithSkipStorage, WithState (to encode state in the
// activation token)
func CreateServerLedActivationToken(
	ctx context.Context,
	storage nodeenrollment.Storage,
	req *types.ServerLedRegistrationRequest,
	opt ...nodeenrollment.Option,
) (string, string, error) {
	const op = "nodeenrollment.registration.RegisterViaServerLedFlow"

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return "", "", fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	switch {
	case req == nil:
		return "", "", fmt.Errorf("(%s) nil request", op)
	case !opts.WithSkipStorage && nodeenrollment.IsNil(storage):
		return "", "", fmt.Errorf("(%s) nil storage", op)
	}

	var (
		tokenEntry = new(types.ServerLedActivationToken)
		tokenNonce = new(types.ServerLedActivationTokenNonce)
	)

	// First create nonce
	{
		tokenNonce.Nonce = make([]byte, nodeenrollment.NonceSize)
		num, err := opts.WithRandomReader.Read(tokenNonce.Nonce)
		switch {
		case err != nil:
			return "", "", fmt.Errorf("(%s) error generating nonce: %w", op, err)
		case num != nodeenrollment.NonceSize:
			return "", "", fmt.Errorf("(%s) read incorrect number of bytes for nonce, wanted %d, got %d", op, nodeenrollment.NonceSize, num)
		}
		tokenEntry.RegistrationChallenge = &types.RegistrationChallenge{
			Challenge: tokenNonce.Nonce,
		}
	}
	// Create a unique hmac key. This is used only to find the entry in storage;
	// it's a weird mechanism but legacy for backwards compat.
	{
		tokenNonce.HmacKeyBytes = make([]byte, 32)
		num, err := opts.WithRandomReader.Read(tokenNonce.HmacKeyBytes)
		switch {
		case err != nil:
			return "", "", fmt.Errorf("(%s) error generating hmac key bytes: %w", op, err)
		case num != 32:
			return "", "", fmt.Errorf("(%s) read incorrect number of bytes for hmac key, wanted %d, got %d", op, nodeenrollment.NonceSize, num)
		}
		// Now, we're going to hmac the nonce; an encoding of the hmac value will
		// give us the ID for storage of the activation token entry.
		hm := hmac.New(sha256.New, tokenNonce.HmacKeyBytes)
		idBytes := hm.Sum(tokenNonce.Nonce)
		tokenEntry.Id = base58.FastBase58Encoding(idBytes)
	}
	// Generate the server-side encryption key that will be used with this node
	{
		tokenNonce.ActivationTokenId = tokenEntry.Id
		tokenEntry.ServerEncryptionPrivateKeyBytes = make([]byte, curve25519.ScalarSize)
		num, err := opts.WithRandomReader.Read(tokenEntry.ServerEncryptionPrivateKeyBytes)
		switch {
		case err != nil:
			return "", "", fmt.Errorf("(%s) error reading random bytes to generate node encryption key: %w", op, err)
		case num != curve25519.ScalarSize:
			return "", "", fmt.Errorf("(%s) wrong number of random bytes read when generating node encryption key, expected %d but got %d", op, curve25519.ScalarSize, num)
		}
		tokenEntry.ServerEncryptionPrivateKeyType = types.KEYTYPE_X25519
		encryptionPrivateKey, err := ecdh.X25519().NewPrivateKey(tokenEntry.ServerEncryptionPrivateKeyBytes)
		if err != nil {
			return "", "", fmt.Errorf("(%s) error reading node private encryption key: %w", op, err)
		}
		tokenNonce.ServerEncryptionPublicKeyBytes = encryptionPrivateKey.PublicKey().Bytes()
		tokenNonce.ServerEncryptionPublicKeyType = types.KEYTYPE_X25519
	}

	// Now generate the returned value that will be transmitted by marshaling the token
	returnedTokenBytes, err := proto.Marshal(tokenNonce)
	if err != nil {
		return "", "", fmt.Errorf("(%s) error marshaling token nonce: %w", op, err)
	}

	tokenEntry.CreationTime = timestamppb.Now()
	tokenEntry.State = opts.WithState

	if !opts.WithSkipStorage {
		// At this point everything is generated and both messages are prepared;
		// store the value
		if err := tokenEntry.Store(ctx, storage, opt...); err != nil {
			return "", "", fmt.Errorf("(%s) error storing activation token: %w", op, err)
		}
	}

	return tokenEntry.Id, fmt.Sprintf("%s%s", nodeenrollment.ServerLedActivationTokenPrefix, base58.FastBase58Encoding(returnedTokenBytes)), nil
}

// validateServerLedActivationToken validates that a token found in a fetch
// request is valid. It returns the authorized NodeInformation.
//
// Supported options: WithMaximumServerLedActivationTokenLifetime; other options
// are passed through to downstream functions.
func validateServerLedActivationToken(
	ctx context.Context,
	storage nodeenrollment.Storage,
	reqInfo *types.FetchNodeCredentialsInfo,
	tokenNonce *types.ServerLedActivationTokenNonce,
	opt ...nodeenrollment.Option,
) (*types.NodeInformation, error) {
	const op = "nodeenrollment.registration.FetchNodeCredentials"

	switch {
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) nil storage", op)
	case reqInfo == nil:
		return nil, fmt.Errorf("(%s) nil request info", op)
	case tokenNonce == nil:
		return nil, fmt.Errorf("(%s) nil token nonce", op)
	case tokenNonce.ActivationTokenId == "" && len(tokenNonce.Nonce) == 0:
		return nil, fmt.Errorf("(%s) empty token nonce nonce", op)
	case tokenNonce.ActivationTokenId == "" && len(tokenNonce.HmacKeyBytes) == 0:
		return nil, fmt.Errorf("(%s) empty token nonce hmac key bytes", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	activationTokenId := tokenNonce.ActivationTokenId
	if activationTokenId == "" {
		// Generate the ID from the token values for lookup
		hm := hmac.New(sha256.New, tokenNonce.HmacKeyBytes)
		idBytes := hm.Sum(tokenNonce.Nonce)
		activationTokenId = base58.FastBase58Encoding(idBytes)
	}
	tokenEntry, err := types.LoadServerLedActivationToken(ctx, storage, activationTokenId, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error looking up activation token: %w", op, err)
	}
	if tokenEntry == nil {
		// Returning ErrNotFound here will result in the Fetch call returning unauthorized
		return nil, fmt.Errorf("(%s) activation token from lookup is nil: %w", op, nodeenrollment.ErrNotFound)
	}

	if tokenEntry.RegistrationChallenge != nil {
		switch {
		case len(tokenEntry.RegistrationChallenge.Challenge) == 0:
			return nil, fmt.Errorf("(%s) missing registration challenge nonce in activation token entry", op)
		}

		if len(reqInfo.EncryptedRegistrationChallenge) > 0 {
			// New protocol: validate proof of the stored challenge encrypted to
			// the server's activation-token key.
			switch {
			case len(tokenEntry.ServerEncryptionPrivateKeyBytes) == 0:
				return nil, fmt.Errorf("(%s) missing server encryption private key bytes in activation token entry", op)
			case len(reqInfo.EncryptionPublicKeyBytes) == 0:
				return nil, fmt.Errorf("(%s) missing encryption public key bytes in req", op)
			}
			ni := &types.NodeInformation{
				ServerEncryptionPrivateKeyBytes: tokenEntry.ServerEncryptionPrivateKeyBytes,
				ServerEncryptionPrivateKeyType:  tokenEntry.ServerEncryptionPrivateKeyType,
				EncryptionPublicKeyBytes:        reqInfo.EncryptionPublicKeyBytes,
				EncryptionPublicKeyType:         reqInfo.EncryptionPublicKeyType,
				CertificatePublicKeyPkix:        reqInfo.CertificatePublicKeyPkix,
			}
			var challenge types.RegistrationChallenge
			if err := nodeenrollment.DecryptMessage(ctx, reqInfo.EncryptedRegistrationChallenge, ni, &challenge); err != nil {
				return nil, fmt.Errorf("(%s) error decrypting registration challenge: %w", op, err)
			}
			if len(challenge.Challenge) == 0 {
				return nil, fmt.Errorf("(%s) decrypted registration challenge nonce is empty", op)
			}
			if subtle.ConstantTimeCompare(challenge.Challenge, tokenEntry.RegistrationChallenge.Challenge) != 1 {
				return nil, fmt.Errorf("(%s) invalid registration challenge nonce", op)
			}
		} else {
			// Legacy worker fallback for controller-first upgrades: require the
			// full legacy token material and validate it against the stored
			// challenge. The public activation token ID alone is not sufficient.
			switch {
			case len(tokenNonce.Nonce) == 0:
				return nil, fmt.Errorf("(%s) missing legacy token nonce", op)
			case len(tokenNonce.HmacKeyBytes) == 0:
				return nil, fmt.Errorf("(%s) missing legacy token hmac key bytes", op)
			}
			hm := hmac.New(sha256.New, tokenNonce.HmacKeyBytes)
			idBytes := hm.Sum(tokenNonce.Nonce)
			legacyActivationTokenId := base58.FastBase58Encoding(idBytes)
			if subtle.ConstantTimeCompare([]byte(legacyActivationTokenId), []byte(activationTokenId)) != 1 {
				return nil, fmt.Errorf("(%s) invalid legacy activation token id", op)
			}
			if subtle.ConstantTimeCompare(tokenNonce.Nonce, tokenEntry.RegistrationChallenge.Challenge) != 1 {
				return nil, fmt.Errorf("(%s) invalid legacy registration challenge nonce", op)
			}
		}

		if len(tokenEntry.ServerEncryptionPrivateKeyBytes) > 0 && tokenEntry.ServerEncryptionPrivateKeyType != types.KEYTYPE_UNSPECIFIED {
			opt = append(opt, nodeenrollment.WithPrivateKey(tokenEntry.ServerEncryptionPrivateKeyBytes, uint(tokenEntry.ServerEncryptionPrivateKeyType)))
		}
	}

	// Validate the time since creation
	switch {
	case tokenEntry.CreationTime == nil:
		return nil, fmt.Errorf("(%s) nil activation token creation time", op)
	case tokenEntry.CreationTime.AsTime().IsZero():
		return nil, fmt.Errorf("(%s) activation token creation time is zero", op)
	}
	if tokenEntry.CreationTime.AsTime().Add(opts.WithMaximumServerLedActivationTokenLifetime).Before(time.Now()) {
		return nil, fmt.Errorf("(%s) activation token has expired", op)
	}

	// If state was provided, use it. Note that it may clash if state is passed
	// into the function directly; either transfer state via token entry, or
	// when calling this function.
	if tokenEntry.State != nil {
		opt = append(opt, nodeenrollment.WithState(tokenEntry.State))
	}

	// We need to remove this since it's one-time-use. Note that it's up to the
	// storage implementation to have this be truly one-time or not (e.g. in a
	// transaction). If possible, storage should communicate anything unexpected
	// (such as the value not being found) as an error so we don't proceed
	// towards authorization.
	if err := storage.Remove(ctx, tokenEntry); err != nil {
		return nil, fmt.Errorf("(%s) error removing server-led activation token: %w", op, err)
	}

	keyId, err := nodeenrollment.KeyIdFromPkix(reqInfo.CertificatePublicKeyPkix)
	if err != nil {
		return nil, fmt.Errorf("(%s) error deriving key id: %w", op, err)
	}

	// Verify that we don't have an authorization already for the given key ID
	if keyCheck, _ := types.LoadNodeInformation(ctx, storage, keyId, opt...); keyCheck != nil {
		return nil, fmt.Errorf("(%s) node cannot be authorized as there is an existing node", op)
	}

	// Authorize the node; we'll then fall through to the rest of the fetch
	// workflow (we've already ensured we're not in an authorize call up
	// above).
	nodeInfo, err := authorizeNodeCommon(ctx, storage, reqInfo, opt...)
	return nodeInfo, err
}
