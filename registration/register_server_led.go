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
// NodeInformation.Store), WithSkipStorage (useful for tests), WithState (to
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
		activationToken = new(types.ServerLedActivationToken)
		bundle          = new(types.ServerLedActivationTokenBundle)
		nodeInfo        = new(types.NodeInformation)
	)

	// First create bundle values. The nonce is to ensure uniqueness of any
	// given bundle.
	bundle.Nonce = make([]byte, nodeenrollment.NonceSize)
	num, err := opts.WithRandomReader.Read(bundle.Nonce)
	switch {
	case err != nil:
		return "", "", fmt.Errorf("(%s) error generating nonce: %w", op, err)
	case num != nodeenrollment.NonceSize:
		return "", "", fmt.Errorf("(%s) read incorrect number of bytes for nonce, wanted %d, got %d", op, nodeenrollment.NonceSize, num)
	}
	bundle.CreationTime = timestamppb.Now()
	bundle.State = opts.WithState

	// Serialize the bundle and store into the activation token
	if activationToken.Bundle, err = proto.Marshal(bundle); err != nil {
		return "", "", fmt.Errorf("(%s) error serializing bundle: %w", op, err)
	}

	// Create a unique hmac key
	activationToken.HmacKeyBytes = make([]byte, nodeenrollment.NonceSize)
	num, err = opts.WithRandomReader.Read(activationToken.HmacKeyBytes)
	switch {
	case err != nil:
		return "", "", fmt.Errorf("(%s) error generating hmac key bytes: %w", op, err)
	case num != nodeenrollment.NonceSize:
		return "", "", fmt.Errorf("(%s) read incorrect number of bytes for hmac key, wanted %d, got %d", op, nodeenrollment.NonceSize, num)
	}

	// Now, we're going to hmac the bundle; an encoding of the hmac value will
	// give us the ID for storage. That way we aren't storing tokens directly as
	// entries in storage.
	hm := hmac.New(sha256.New, activationToken.HmacKeyBytes)
	idBytes := hm.Sum(activationToken.Bundle)
	nodeInfo.Id = fmt.Sprintf("%s%s", nodeenrollment.ServerLedActivationTokenPrefix, base58.FastBase58Encoding(idBytes))

	// Now generate the nonce that will be transmitted by marshaling the token
	if nodeInfo.RegistrationNonce, err = proto.Marshal(activationToken); err != nil {
		return "", "", fmt.Errorf("(%s) error marshaling token: %w", op, err)
	}

	if !opts.WithSkipStorage {
		// At this point everything is generated and both messages are prepared;
		// store the value
		if err := nodeInfo.Store(ctx, storage, opt...); err != nil {
			return "", "", fmt.Errorf("(%s) error storing node information: %w", op, err)
		}
	}

	return nodeInfo.Id, fmt.Sprintf("%s%s", nodeenrollment.ServerLedActivationTokenPrefix, base58.FastBase58Encoding(nodeInfo.RegistrationNonce)), nil
}
