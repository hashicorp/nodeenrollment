// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package registration_test

import (
	"context"
	"testing"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/inmem"
	"github.com/hashicorp/nodeenrollment/storage/inmem/storeonce"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestAuthorizeNode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fileStorage, err := inmem.New(ctx)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(ctx, fileStorage)
	require.NoError(t, err)

	// This happens on the node
	nodeCreds, err := types.NewNodeCredentials(ctx, fileStorage)
	require.NoError(t, err)
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)
	keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)
	nodePubKey, err := curve25519.X25519(nodeCreds.EncryptionPrivateKeyBytes, curve25519.Basepoint)
	require.NoError(t, err)

	structMap := map[string]interface{}{"foo": "bar"}
	state, err := structpb.NewStruct(structMap)
	require.NoError(t, err)

	// Add in node information to storage so we have a key to use
	nodeInfo := &types.NodeInformation{
		Id:                       keyId,
		CertificatePublicKeyPkix: nodeCreds.CertificatePublicKeyPkix,
		CertificatePublicKeyType: nodeCreds.CertificatePrivateKeyType,
		EncryptionPublicKeyBytes: nodePubKey,
		EncryptionPublicKeyType:  nodeCreds.EncryptionPrivateKeyType,
		RegistrationNonce:        nodeCreds.RegistrationNonce,
		State:                    state,
	}

	tests := []struct {
		name string
		// Flag to insert node information in advance
		prepopulatedNodeInfo bool
		// Flag to set storage to nil
		storageNil bool
	}{
		{
			name:       "invalid-no-storage",
			storageNil: true,
		},
		{
			name: "valid",
		},
		// Leave this after "valid" so it checks when it's already there
		{
			name:                 "invalid-already-authorized",
			prepopulatedNodeInfo: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			storage := fileStorage
			var wantErrContains string

			if tt.storageNil {
				storage = nil
				wantErrContains = "nil storage" // this doesn't overlap in test cases
			}

			if tt.prepopulatedNodeInfo {
				wantErrContains = "existing node"
			}

			_, err := registration.AuthorizeNode(ctx, storage, fetchReq)
			switch wantErrContains {
			case "":
				require.NoError(err)
			default:
				require.Error(err)
				assert.Contains(err.Error(), wantErrContains)
				return
			}

			checkNodeInfo := &types.NodeInformation{Id: nodeInfo.Id}
			require.NoError(storage.Load(ctx, checkNodeInfo))
			require.NotNil(checkNodeInfo)
			assert.Equal(nodeInfo.Id, checkNodeInfo.Id)
			assert.NotEmpty(checkNodeInfo.CertificatePublicKeyPkix)
			assert.Equal(types.KEYTYPE_ED25519, checkNodeInfo.CertificatePublicKeyType)
			assert.Len(checkNodeInfo.CertificateBundles, 2)
			for _, bundle := range checkNodeInfo.CertificateBundles {
				assert.NotEmpty(bundle.CertificateDer)
				assert.NotEmpty(bundle.CaCertificateDer)
				assert.NoError(bundle.CertificateNotBefore.CheckValid())
				assert.False(bundle.CertificateNotBefore.AsTime().IsZero())
				assert.NoError(bundle.CertificateNotAfter.CheckValid())
				assert.False(bundle.CertificateNotAfter.AsTime().IsZero())
			}
			assert.NotEmpty(checkNodeInfo.EncryptionPublicKeyBytes)
			assert.Equal(types.KEYTYPE_X25519, checkNodeInfo.EncryptionPublicKeyType)
			assert.NotEmpty(checkNodeInfo.ServerEncryptionPrivateKeyBytes)
			assert.Equal(types.KEYTYPE_X25519, checkNodeInfo.ServerEncryptionPrivateKeyType)
			assert.Len(checkNodeInfo.RegistrationNonce, nodeenrollment.NonceSize)
		})
	}
}

func TestAuthorizeNodeCommon_DuplicateStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fileStorage, err := storeonce.New(ctx)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(ctx, fileStorage)
	require.NoError(t, err)

	// This happens on the node
	nodeCreds, err := types.NewNodeCredentials(ctx, fileStorage)
	require.NoError(t, err)
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)
	keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)
	nodePubKey, err := curve25519.X25519(nodeCreds.EncryptionPrivateKeyBytes, curve25519.Basepoint)
	require.NoError(t, err)

	structMap := map[string]interface{}{"foo": "bar"}
	state, err := structpb.NewStruct(structMap)
	require.NoError(t, err)

	// Add in node information to storage so we have a key to use
	nodeInfo := &types.NodeInformation{
		Id:                       keyId,
		CertificatePublicKeyPkix: nodeCreds.CertificatePublicKeyPkix,
		CertificatePublicKeyType: nodeCreds.CertificatePrivateKeyType,
		EncryptionPublicKeyBytes: nodePubKey,
		EncryptionPublicKeyType:  nodeCreds.EncryptionPrivateKeyType,
		RegistrationNonce:        nodeCreds.RegistrationNonce,
		State:                    state,
	}

	fetchInfo, _ := registration.ValidateFetchRequestCommon(ctx, fileStorage, fetchReq)
	_, err = registration.AuthorizeNodeCommon(ctx, fileStorage, fetchInfo)
	require.NoError(t, err)

	checkNodeInfo := &types.NodeInformation{Id: nodeInfo.Id}
	require.NoError(t, fileStorage.Load(ctx, checkNodeInfo))
	require.NotNil(t, checkNodeInfo)
	assert.Equal(t, nodeInfo.Id, checkNodeInfo.Id)
	assert.NotEmpty(t, checkNodeInfo.CertificatePublicKeyPkix)
	assert.Equal(t, types.KEYTYPE_ED25519, checkNodeInfo.CertificatePublicKeyType)
	assert.Len(t, checkNodeInfo.CertificateBundles, 2)
	for _, bundle := range checkNodeInfo.CertificateBundles {
		assert.NotEmpty(t, bundle.CertificateDer)
		assert.NotEmpty(t, bundle.CaCertificateDer)
		assert.NoError(t, bundle.CertificateNotBefore.CheckValid())
		assert.False(t, bundle.CertificateNotBefore.AsTime().IsZero())
		assert.NoError(t, bundle.CertificateNotAfter.CheckValid())
		assert.False(t, bundle.CertificateNotAfter.AsTime().IsZero())
	}
	assert.NotEmpty(t, checkNodeInfo.EncryptionPublicKeyBytes)
	assert.Equal(t, types.KEYTYPE_X25519, checkNodeInfo.EncryptionPublicKeyType)
	assert.NotEmpty(t, checkNodeInfo.ServerEncryptionPrivateKeyBytes)
	assert.Equal(t, types.KEYTYPE_X25519, checkNodeInfo.ServerEncryptionPrivateKeyType)
	assert.Len(t, checkNodeInfo.RegistrationNonce, nodeenrollment.NonceSize)

	// Simulate a withWrapper case where we might hit authorizeNodeCommon a second time
	returnedNodeInfo, err := registration.AuthorizeNodeCommon(ctx, fileStorage, fetchInfo)
	require.NoError(t, err)
	require.Equal(t, checkNodeInfo, returnedNodeInfo)
}
