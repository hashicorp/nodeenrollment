// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package registration

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
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
		tokenEntry.Id = serverLedActivationTokenId(tokenNonce.Nonce, tokenNonce.HmacKeyBytes)
		tokenNonce.ActivationTokenId = tokenEntry.Id
	}
	// Generate the server-side encryption key that will be used with this node
	{
		switch {
		case opts.WithEncryptionPrivateKeyType == uint(types.KEYTYPE_MLKEM1024),
			opts.WithEncryptionPrivateKeyType == uint(types.KEYTYPE_UNSPECIFIED):
			decapsulationKey, err := mlkem.GenerateKey1024()
			if err != nil {
				return "", "", fmt.Errorf("(%s) error generating mlkem decapsulation key: %w", op, err)
			}
			tokenEntry.MlkemParameters = &types.MLKEMParameters{
				DecapsulationKey: decapsulationKey.Bytes(),
			}
			tokenEntry.ServerEncryptionPrivateKeyType = types.KEYTYPE_MLKEM1024
			tokenNonce.ServerEncryptionPublicKeyType = types.KEYTYPE_MLKEM1024
			tokenNonce.MlkemEncapsulationKeyBytes = decapsulationKey.EncapsulationKey().Bytes()
		case opts.WithEncryptionPrivateKeyType == uint(types.KEYTYPE_X25519):
			tokenEntry.ServerEncryptionPrivateKeyBytes = make([]byte, curve25519.ScalarSize)
			num, err := opts.WithRandomReader.Read(tokenEntry.ServerEncryptionPrivateKeyBytes)
			switch {
			case err != nil:
				return "", "", fmt.Errorf("(%s) error reading random bytes to generate node encryption key: %w", op, err)
			case num != curve25519.ScalarSize:
				return "", "", fmt.Errorf("(%s) wrong number of random bytes read when generating node encryption key, expected %d but got %d", op, curve25519.ScalarSize, num)
			}
			encryptionPrivateKey, err := ecdh.X25519().NewPrivateKey(tokenEntry.ServerEncryptionPrivateKeyBytes)
			if err != nil {
				return "", "", fmt.Errorf("(%s) error reading node private encryption key: %w", op, err)
			}
			tokenEntry.ServerEncryptionPrivateKeyType = types.KEYTYPE_X25519
			tokenNonce.ServerEncryptionPublicKeyType = types.KEYTYPE_X25519
			tokenNonce.ServerEncryptionPublicKeyBytes = encryptionPrivateKey.PublicKey().Bytes()
		default:
			return "", "", fmt.Errorf("(%s) unsupported encryption private key type: %s", op, types.KEYTYPE(opts.WithEncryptionPrivateKeyType).String())
		}
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

func serverLedActivationTokenId(nonce, hmacKey []byte) string {
	hm := hmac.New(sha256.New, hmacKey)
	hm.Write(nonce)
	return base58.FastBase58Encoding(hm.Sum(nil))
}

func legacyServerLedActivationTokenId(nonce, hmacKey []byte) string {
	hm := hmac.New(sha256.New, hmacKey)
	return base58.FastBase58Encoding(hm.Sum(nonce))
}

func serverLedActivationTokenIdMatches(id string, tokenNonce *types.ServerLedActivationTokenNonce) bool {
	if tokenNonce == nil || len(tokenNonce.Nonce) == 0 || len(tokenNonce.HmacKeyBytes) == 0 {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(serverLedActivationTokenId(tokenNonce.Nonce, tokenNonce.HmacKeyBytes)), []byte(id)) == 1 {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(legacyServerLedActivationTokenId(tokenNonce.Nonce, tokenNonce.HmacKeyBytes)), []byte(id)) == 1
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
		activationTokenId = serverLedActivationTokenId(tokenNonce.Nonce, tokenNonce.HmacKeyBytes)
	}
	tokenEntry, err := types.LoadServerLedActivationToken(ctx, storage, activationTokenId, opt...)
	if err != nil && errors.Is(err, nodeenrollment.ErrNotFound) && len(tokenNonce.Nonce) > 0 && len(tokenNonce.HmacKeyBytes) > 0 {
		legacyActivationTokenId := legacyServerLedActivationTokenId(tokenNonce.Nonce, tokenNonce.HmacKeyBytes)
		if legacyActivationTokenId != activationTokenId {
			tokenEntry, err = types.LoadServerLedActivationToken(ctx, storage, legacyActivationTokenId, opt...)
			if err == nil {
				activationTokenId = legacyActivationTokenId
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("(%s) error looking up activation token: %w", op, err)
	}
	if tokenEntry == nil {
		// Returning ErrNotFound here will result in the Fetch call returning unauthorized
		return nil, fmt.Errorf("(%s) activation token from lookup is nil: %w", op, nodeenrollment.ErrNotFound)
	}

	// Validate/derive encryption keys if available
	switch {
	case tokenEntry.ServerEncryptionPrivateKeyType == types.KEYTYPE_X25519:
		switch {
		case reqInfo.EncryptionPublicKeyType != types.KEYTYPE_X25519:
			return nil, fmt.Errorf("(%s) request encryption public key type %s does not match activation token key type %s", op, reqInfo.EncryptionPublicKeyType.String(), tokenEntry.ServerEncryptionPrivateKeyType.String())
		case len(tokenEntry.ServerEncryptionPrivateKeyBytes) == 0:
			return nil, fmt.Errorf("(%s) missing server encryption private key bytes in activation token entry", op)
		case len(reqInfo.EncryptionPublicKeyBytes) == 0:
			return nil, fmt.Errorf("(%s) missing encryption public key bytes in req", op)
		}
		opt = append(opt, nodeenrollment.WithEncryptionPrivateKey(tokenEntry.ServerEncryptionPrivateKeyBytes, uint(tokenEntry.ServerEncryptionPrivateKeyType)))
	case tokenEntry.ServerEncryptionPrivateKeyType == types.KEYTYPE_MLKEM1024:
		switch {
		case reqInfo.EncryptionPublicKeyType != types.KEYTYPE_MLKEM1024:
			return nil, fmt.Errorf("(%s) request encryption public key type %s does not match activation token key type %s", op, reqInfo.EncryptionPublicKeyType.String(), tokenEntry.ServerEncryptionPrivateKeyType.String())
		case tokenEntry.MlkemParameters == nil:
			return nil, fmt.Errorf("(%s) missing mlkem parameters in activation token entry", op)
		case len(tokenEntry.MlkemParameters.DecapsulationKey) == 0:
			return nil, fmt.Errorf("(%s) missing mlkem decapsulation key in activation token entry", op)
		case reqInfo.MlkemParameters == nil:
			return nil, fmt.Errorf("(%s) missing mlkem parameters in request info", op)
		case len(reqInfo.MlkemParameters.Ciphertext) == 0:
			return nil, fmt.Errorf("(%s) missing mlkem ciphertext in request info", op)
		case len(reqInfo.MlkemParameters.EncapsulationKey) == 0:
			return nil, fmt.Errorf("(%s) missing mlkem encapsulation key bytes in request info", op)
		}
		decapKey, err := mlkem.NewDecapsulationKey1024(tokenEntry.MlkemParameters.DecapsulationKey)
		if err != nil {
			return nil, fmt.Errorf("(%s) error reading mlkem decapsulation key from activation token entry: %w", op, err)
		}
		// This is just a check for accidentally passing the wrong
		// ciphertext, to make sure it was made by this key
		if subtle.ConstantTimeCompare(decapKey.EncapsulationKey().Bytes(), reqInfo.MlkemParameters.EncapsulationKey) != 1 {
			return nil, fmt.Errorf("(%s) mlkem decapsulation key in request does not match activation token entry", op)
		}
		tokenEntry.MlkemParameters.Ciphertext = reqInfo.MlkemParameters.Ciphertext
		sharedKey, err := decapKey.Decapsulate(reqInfo.MlkemParameters.Ciphertext)
		if err != nil {
			return nil, fmt.Errorf("(%s) error decapsulating mlkem shared key: %w", op, err)
		}
		tokenEntry.MlkemParameters.SharedKey = sharedKey
		tokenEntry.MlkemParameters.DecapsulationKey = nil // zero out the decapsulation key since we won't need it again and it's sensitive material
		opt = append(opt, nodeenrollment.WithMlkemParameters(tokenEntry.MlkemParameters))
	case tokenEntry.ServerEncryptionPrivateKeyType == types.KEYTYPE_UNSPECIFIED:
		// Legacy tokens (stored before key type was tracked) fall through to the
		// legacy nonce/challenge validation below, however, if the key exists
		// provide the key to ensure we don't generate a fresh one. This is an
		// upgrade unlikely corner case.
		if len(tokenEntry.ServerEncryptionPrivateKeyBytes) != 0 && reqInfo.EncryptionPublicKeyType != types.KEYTYPE_UNSPECIFIED {
			opt = append(opt, nodeenrollment.WithEncryptionPrivateKey(tokenEntry.ServerEncryptionPrivateKeyBytes, uint(reqInfo.EncryptionPublicKeyType)))
		}
	default:
		return nil, fmt.Errorf("(%s) unknown server encryption private key type in activation token entry: %d", op, tokenEntry.ServerEncryptionPrivateKeyType)
	}

	if tokenEntry.RegistrationChallenge != nil {
		switch {
		case len(tokenEntry.RegistrationChallenge.Challenge) == 0:
			return nil, fmt.Errorf("(%s) missing registration challenge nonce in activation token entry", op)
		}

		if len(reqInfo.EncryptedRegistrationChallenge) > 0 {
			ni := &types.NodeInformation{
				ServerEncryptionPrivateKeyType:  tokenEntry.ServerEncryptionPrivateKeyType,
				ServerEncryptionPrivateKeyBytes: tokenEntry.ServerEncryptionPrivateKeyBytes,
				EncryptionPublicKeyType:         reqInfo.EncryptionPublicKeyType,
				EncryptionPublicKeyBytes:        reqInfo.EncryptionPublicKeyBytes,
				MlkemParameters:                 tokenEntry.MlkemParameters,
				CertificatePublicKeyPkix:        reqInfo.CertificatePublicKeyPkix,
			}
			// New protocol: validate proof of the stored challenge encrypted to
			// the server's activation-token key.
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
			if !serverLedActivationTokenIdMatches(activationTokenId, tokenNonce) {
				return nil, fmt.Errorf("(%s) invalid legacy activation token id", op)
			}
			if subtle.ConstantTimeCompare(tokenNonce.Nonce, tokenEntry.RegistrationChallenge.Challenge) != 1 {
				return nil, fmt.Errorf("(%s) invalid legacy registration challenge nonce", op)
			}
		}
	} else {
		// Old stored server-led activation tokens do not have a challenge. They
		// must still prove possession of the full legacy token material; the
		// storage ID alone is public and must not authorize registration.
		switch {
		case len(tokenNonce.Nonce) == 0:
			return nil, fmt.Errorf("(%s) missing legacy token nonce", op)
		case len(tokenNonce.HmacKeyBytes) == 0:
			return nil, fmt.Errorf("(%s) missing legacy token hmac key bytes", op)
		case !serverLedActivationTokenIdMatches(activationTokenId, tokenNonce):
			return nil, fmt.Errorf("(%s) invalid legacy activation token id", op)
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
