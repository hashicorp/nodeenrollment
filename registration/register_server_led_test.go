package registration

import (
	"context"
	"testing"

	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerLedRegistration(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()

	storage, err := file.NewFileStorage(ctx)
	require.NoError(err)
	t.Cleanup(storage.Cleanup)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(err)

	// Ensure nil request and/or storage are caught
	nodeCreds, err := RegisterViaServerLedFlow(ctx, nil, &types.ServerLedRegistrationRequest{})
	require.Error(err)
	assert.Contains(err.Error(), "nil storage")
	assert.Nil(nodeCreds)
	nodeCreds, err = RegisterViaServerLedFlow(ctx, storage, nil)
	require.Error(err)
	assert.Contains(err.Error(), "nil request")
	assert.Nil(nodeCreds)

	wrapper := aead.TestWrapper(t)

	nodeCreds, err = RegisterViaServerLedFlow(ctx, storage, &types.ServerLedRegistrationRequest{}, nodeenrollment.WithWrapper(wrapper))
	require.NoError(err)
	assert.Empty(nodeCreds.Id)
	assert.NotEmpty(nodeCreds.CertificatePublicKeyPkix)
	assert.NotEmpty(nodeCreds.CertificatePrivateKeyPkcs8)
	assert.Equal(types.KEYTYPE_ED25519, nodeCreds.CertificatePrivateKeyType)
	assert.Len(nodeCreds.CertificateBundles, 2)
	for _, bundle := range nodeCreds.CertificateBundles {
		assert.NotEmpty(bundle.CertificateDer)
		assert.NotEmpty(bundle.CaCertificateDer)
		assert.NoError(bundle.CertificateNotBefore.CheckValid())
		assert.False(bundle.CertificateNotBefore.AsTime().IsZero())
		assert.NoError(bundle.CertificateNotAfter.CheckValid())
		assert.False(bundle.CertificateNotAfter.AsTime().IsZero())
	}
	assert.NotEmpty(nodeCreds.EncryptionPrivateKeyBytes)
	assert.Equal(types.KEYTYPE_X25519, nodeCreds.EncryptionPrivateKeyType)
	assert.NotEmpty(nodeCreds.ServerEncryptionPublicKeyBytes)
	assert.Equal(types.KEYTYPE_X25519, nodeCreds.ServerEncryptionPublicKeyType)
	assert.Empty(nodeCreds.RegistrationNonce)
	assert.Empty(nodeCreds.WrappingKeyId)

	// We should now look for a NodeInformation value in storage and validate it
	keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	require.NoError(err)
	nodeInfo, err := types.LoadNodeInformation(ctx, storage, keyId, nodeenrollment.WithWrapper(wrapper))
	require.NoError(err)
	require.NotNil(nodeInfo)
	assert.NotEmpty(nodeInfo.Id)
	assert.NotEmpty(nodeInfo.CertificatePublicKeyPkix)
	assert.Equal(types.KEYTYPE_ED25519, nodeInfo.CertificatePublicKeyType)
	assert.Len(nodeInfo.CertificateBundles, 2)
	for _, bundle := range nodeInfo.CertificateBundles {
		assert.NotEmpty(bundle.CertificateDer)
		assert.NotEmpty(bundle.CaCertificateDer)
		assert.NoError(bundle.CertificateNotBefore.CheckValid())
		assert.False(bundle.CertificateNotBefore.AsTime().IsZero())
		assert.NoError(bundle.CertificateNotAfter.CheckValid())
		assert.False(bundle.CertificateNotAfter.AsTime().IsZero())
	}
	assert.NotEmpty(nodeInfo.EncryptionPublicKeyBytes)
	assert.Equal(types.KEYTYPE_X25519, nodeInfo.EncryptionPublicKeyType)
	assert.NotEmpty(nodeInfo.ServerEncryptionPrivateKeyBytes)
	assert.Equal(types.KEYTYPE_X25519, nodeInfo.ServerEncryptionPrivateKeyType)
	assert.Empty(nodeInfo.RegistrationNonce)
	assert.Empty(nodeInfo.WrappingKeyId)
}
