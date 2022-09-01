package registration

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
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
// Supported options: WithRandomReader, WithWrapper (passed through to
// NodeInformation.Store), WithSkipStorage, WithState (to
// encode state in the activation token)
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

	// First create nonce values
	tokenNonce.Nonce = make([]byte, nodeenrollment.NonceSize)
	num, err := opts.WithRandomReader.Read(tokenNonce.Nonce)
	switch {
	case err != nil:
		return "", "", fmt.Errorf("(%s) error generating nonce: %w", op, err)
	case num != nodeenrollment.NonceSize:
		return "", "", fmt.Errorf("(%s) read incorrect number of bytes for nonce, wanted %d, got %d", op, nodeenrollment.NonceSize, num)
	}
	// Create a unique hmac key
	tokenNonce.HmacKeyBytes = make([]byte, 32)
	num, err = opts.WithRandomReader.Read(tokenNonce.HmacKeyBytes)
	switch {
	case err != nil:
		return "", "", fmt.Errorf("(%s) error generating hmac key bytes: %w", op, err)
	case num != 32:
		return "", "", fmt.Errorf("(%s) read incorrect number of bytes for hmac key, wanted %d, got %d", op, nodeenrollment.NonceSize, num)
	}

	// Now generate the returned value that will be transmitted by marshaling the token
	returnedTokenBytes, err := proto.Marshal(tokenNonce)
	if err != nil {
		return "", "", fmt.Errorf("(%s) error marshaling token nonce: %w", op, err)
	}

	tokenEntry.CreationTime = timestamppb.Now()
	tokenEntry.State = opts.WithState

	// Now, we're going to hmac the nonce; an encoding of the hmac value will
	// give us the ID for storage of the activation token entry. That way we
	// aren't storing usable values directly as entries in storage.
	hm := hmac.New(sha256.New, tokenNonce.HmacKeyBytes)
	idBytes := hm.Sum(tokenNonce.Nonce)
	tokenEntry.Id = base58.FastBase58Encoding(idBytes)

	if !opts.WithSkipStorage {
		// At this point everything is generated and both messages are prepared;
		// store the value
		if err := tokenEntry.Store(ctx, storage, opt...); err != nil {
			return "", "", fmt.Errorf("(%s) error storing activation token: %w", op, err)
		}
	}

	return tokenEntry.Id, fmt.Sprintf("%s%s", nodeenrollment.ServerLedActivationTokenPrefix, base58.FastBase58Encoding(returnedTokenBytes)), nil
}
