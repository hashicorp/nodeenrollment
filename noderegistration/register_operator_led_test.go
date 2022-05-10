package noderegistration

import (
	"context"
	"testing"

	"github.com/hashicorp/nodeenrollment/nodestorage/file"
	"github.com/hashicorp/nodeenrollment/nodetypes"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOperatorRegistration_Basic(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()

	storage, err := file.NewFileStorage(ctx)
	require.NoError(err)
	t.Cleanup(storage.Cleanup)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(err)

	nodeCreds, err := RegisterViaOperatorLedFlow(ctx, storage, &nodetypes.OperatorLedRegistrationRequest{})
	require.NoError(err)
	assert.Empty(nodeCreds.Id)
	assert.NotEmpty(nodeCreds.CertificatePublicKeyPkix)
	assert.Len(nodeCreds.CertificateBundles, 2)
	assert.NotEmpty(nodeCreds.CertificatePrivateKeyPkcs8)
	assert.Equal(nodetypes.KEYTYPE_KEYTYPE_ED25519, nodeCreds.CertificatePrivateKeyType)
	assert.NotEmpty(nodeCreds.EncryptionPrivateKeyBytes)
	assert.Equal(nodetypes.KEYTYPE_KEYTYPE_X25519, nodeCreds.EncryptionPrivateKeyType)
	assert.NotEmpty(nodeCreds.ServerEncryptionPublicKeyBytes)
	assert.Equal(nodetypes.KEYTYPE_KEYTYPE_X25519, nodeCreds.ServerEncryptionPublicKeyType)

	// We should now look for a value in storage and validate it
	nodeInfos, err := storage.List(ctx, (*nodetypes.NodeInformation)(nil))
	require.NoError(err)
	require.NotEmpty(nodeInfos)
	assert.Len(nodeInfos, 1)
	nodeInfo := &nodetypes.NodeInformation{Id: nodeInfos[0]}
	require.NoError(storage.Load(ctx, nodeInfo))
	require.NoError(err)
	require.NotNil(nodeInfo)
	assert.Len(nodeInfo.CertificateBundles, 2)
	assert.Equal(nodetypes.KEYTYPE_KEYTYPE_ED25519, nodeInfo.CertificatePublicKeyType)
	assert.NotEmpty(nodeInfo.Id)
	assert.NotEmpty(nodeInfo.CertificatePublicKeyPkix)
	assert.NotEmpty(nodeInfo.EncryptionPublicKeyBytes)
	assert.Equal(nodetypes.KEYTYPE_KEYTYPE_X25519, nodeInfo.EncryptionPublicKeyType)
	assert.NotEmpty(nodeInfo.ServerEncryptionPrivateKeyBytes)
	assert.Equal(nodetypes.KEYTYPE_KEYTYPE_X25519, nodeInfo.ServerEncryptionPrivateKeyType)
}
