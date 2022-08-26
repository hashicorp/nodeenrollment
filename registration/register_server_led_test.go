package registration_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestServerLedRegistration(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()

	storage, err := file.New(ctx)
	require.NoError(err)
	t.Cleanup(storage.Cleanup)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(err)

	// Ensure nil request and/or storage are caught
	_, token, err := registration.CreateServerLedActivationToken(ctx, nil, &types.ServerLedRegistrationRequest{})
	require.Error(err)
	assert.Contains(err.Error(), "nil storage")
	assert.Empty(token)
	_, token, err = registration.CreateServerLedActivationToken(ctx, storage, nil)
	require.Error(err)
	assert.Contains(err.Error(), "nil request")
	assert.Empty(token)

	wrapper := aead.TestWrapper(t)

	var tokenId string
	tokenId, token, err = registration.CreateServerLedActivationToken(ctx, storage, &types.ServerLedRegistrationRequest{}, nodeenrollment.WithWrapper(wrapper))
	require.NoError(err)
	assert.NotEmpty(token)
	assert.True(strings.HasPrefix(token, nodeenrollment.ServerLedActivationTokenPrefix))

	nonce, err := base58.FastBase58Decoding(strings.TrimPrefix(token, nodeenrollment.ServerLedActivationTokenPrefix))
	require.NoError(err)

	// We should now look for a NodeInformation value in storage and validate it
	activationToken := new(types.ServerLedActivationToken)
	require.NoError(proto.Unmarshal(nonce, activationToken))
	nodeInfo, err := types.LoadNodeInformation(ctx, storage, tokenId, nodeenrollment.WithWrapper(wrapper))
	require.NoError(err)
	require.NotNil(nodeInfo)
	assert.NotEmpty(nodeInfo.Id)
	assert.Empty(nodeInfo.CertificatePublicKeyPkix)
	assert.Equal(types.KEYTYPE_UNSPECIFIED, nodeInfo.CertificatePublicKeyType)
	assert.Len(nodeInfo.CertificateBundles, 0)
	assert.Empty(nodeInfo.EncryptionPublicKeyBytes)
	assert.Equal(types.KEYTYPE_UNSPECIFIED, nodeInfo.EncryptionPublicKeyType)
	assert.Empty(nodeInfo.ServerEncryptionPrivateKeyBytes)
	assert.Equal(types.KEYTYPE_UNSPECIFIED, nodeInfo.ServerEncryptionPrivateKeyType)
	assert.NotEmpty(nodeInfo.RegistrationNonce)
	assert.Empty(nodeInfo.WrappingKeyId)
	assert.Equal(nodeInfo.RegistrationNonce, nonce)
}
