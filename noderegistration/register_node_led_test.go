package noderegistration

import (
	"context"
	"testing"

	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/nodestorage/file"
	"github.com/hashicorp/nodeenrollment/nodetypes"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNodeLedRegistration_Basic(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()

	storage, err := file.NewFileStorage(ctx)
	require.NoError(err)
	t.Cleanup(storage.Cleanup)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(err)

	// This happens on the node
	nodeCreds := new(nodetypes.NodeCredentials)
	require.NoError(nodeCreds.GenerateRegistrationParameters(ctx, storage))
	require.NoError(err)

	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(err)
	assert.NotNil(fetchReq)
	assert.NotNil(fetchReq.Bundle)
	assert.NotEmpty(fetchReq.BundleSignature)
	var fetchReqInfo nodetypes.FetchNodeCredentialsInfo
	require.NoError(proto.Unmarshal(fetchReq.Bundle, &fetchReqInfo))
	assert.NotEmpty(fetchReqInfo.CertificatePublicKeyPkix)
	assert.Equal(nodetypes.KEYTYPE_KEYTYPE_ED25519, fetchReqInfo.CertificatePublicKeyType)
	assert.NotEmpty(fetchReqInfo.EncryptionPublicKeyBytes)
	assert.Equal(nodetypes.KEYTYPE_KEYTYPE_X25519, fetchReqInfo.EncryptionPublicKeyType)
	assert.Len(fetchReqInfo.Nonce, nodee.NonceSize)

	// The node starts trying to fetch but nothing should be there yet
	fetchResp, err := FetchNodeCredentials(
		ctx,
		storage,
		fetchReq,
	)
	require.NoError(err)
	require.NotNil(fetchResp)
	assert.False(fetchResp.Authorized)

	// This happens on the server
	require.NoError(AuthorizeNode(
		ctx,
		storage,
		nodee.KeyIdFromPkix(fetchReqInfo.CertificatePublicKeyPkix),
	))

	// We should now look for a node information value in storage and validate that it's populated
	nodeInfos, err := storage.List(ctx, (*nodetypes.NodeInformation)(nil))
	require.NoError(err)
	require.NotEmpty(nodeInfos)
	assert.Len(nodeInfos, 1)
	nodeInfo := &nodetypes.NodeInformation{Id: nodeInfos[0]}
	require.NoError(storage.Load(ctx, nodeInfo))
	require.NotNil(nodeInfo)
	assert.True(nodeInfo.Authorized)
	assert.NotNil(nodeInfo.FirstSeen)
	assert.Len(nodeInfo.CertificateBundles, 2)
	assert.Equal(nodetypes.KEYTYPE_KEYTYPE_ED25519, nodeInfo.CertificatePublicKeyType)
	assert.NotEmpty(nodeInfo.Id)
	assert.NotEmpty(nodeInfo.CertificatePublicKeyPkix)
	assert.NotEmpty(nodeInfo.EncryptionPublicKeyBytes)
	assert.Equal(nodetypes.KEYTYPE_KEYTYPE_X25519, nodeInfo.EncryptionPublicKeyType)
	assert.NotEmpty(nodeInfo.ServerEncryptionPrivateKeyBytes)
	assert.Equal(nodetypes.KEYTYPE_KEYTYPE_X25519, nodeInfo.ServerEncryptionPrivateKeyType)
	assert.Len(nodeInfo.RegistrationNonce, nodee.NonceSize)

	// Now it should show up when the node requests it
	fetchResp, err = FetchNodeCredentials(
		ctx,
		storage,
		fetchReq,
	)
	require.NoError(err)
	assert.NotEmpty(fetchResp.EncryptedNodeCredentials)
	assert.NotEmpty(fetchResp.ServerEncryptionPublicKeyBytes)
	assert.True(fetchResp.Authorized)
	assert.Equal(nodetypes.KEYTYPE_KEYTYPE_X25519, fetchResp.ServerEncryptionPublicKeyType)

	require.NoError(nodeCreds.HandleFetchNodeCredentialsResponse(
		ctx,
		storage,
		fetchResp,
	))
	require.NoError(err)
	assert.NotEmpty(nodeCreds.Id)
	assert.NotEmpty(nodeCreds.CertificatePublicKeyPkix)
	assert.Len(nodeCreds.CertificateBundles, 2)
	assert.NotEmpty(nodeCreds.CertificatePrivateKeyPkcs8)
	assert.Equal(nodetypes.KEYTYPE_KEYTYPE_ED25519, nodeCreds.CertificatePrivateKeyType)
	assert.NotEmpty(nodeCreds.EncryptionPrivateKeyBytes)
	assert.Equal(nodetypes.KEYTYPE_KEYTYPE_X25519, nodeCreds.EncryptionPrivateKeyType)
	assert.NotEmpty(nodeCreds.ServerEncryptionPublicKeyBytes)
	assert.Equal(nodetypes.KEYTYPE_KEYTYPE_X25519, nodeCreds.ServerEncryptionPublicKeyType)
}
