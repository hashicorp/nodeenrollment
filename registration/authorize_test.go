// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package registration_test

import (
	"context"
	"testing"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/inmem"
	testing2 "github.com/hashicorp/nodeenrollment/storage/testing"
	"github.com/hashicorp/nodeenrollment/types"
	nodetesting "github.com/hashicorp/nodeenrollment/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthorizeNode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, kt := range nodetesting.TestKeyTypeVariants() {
		t.Run(kt.Name, func(t *testing.T) {
			t.Parallel()

			storage, err := inmem.New(ctx)
			require.NoError(t, err)

			_, err = rotation.RotateRootCertificates(ctx, storage)
			require.NoError(t, err)

			// This happens on the node
			nodeCreds, err := types.NewNodeCredentials(ctx, storage, kt.Opts...)
			require.NoError(t, err)
			fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
			require.NoError(t, err)
			keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
			require.NoError(t, err)

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

					var wantErrContains string
					localStorage := storage

					if tt.storageNil {
						localStorage = nil
						wantErrContains = "nil storage" // this doesn't overlap in test cases
					}

					if tt.prepopulatedNodeInfo {
						wantErrContains = "existing node"
					}

					_, err := registration.AuthorizeNode(ctx, localStorage, fetchReq)
					switch wantErrContains {
					case "":
						require.NoError(err)
					default:
						require.Error(err)
						assert.Contains(err.Error(), wantErrContains)
						return
					}

					checkNodeInfo := &types.NodeInformation{Id: keyId}
					require.NoError(localStorage.Load(ctx, checkNodeInfo))
					require.NotNil(checkNodeInfo)
					assert.Equal(keyId, checkNodeInfo.Id)
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
					assert.Equal(kt.KeyType, checkNodeInfo.EncryptionPublicKeyType)
					assert.Equal(kt.KeyType, checkNodeInfo.ServerEncryptionPrivateKeyType)
					if kt.KeyType == types.KEYTYPE_X25519 {
						assert.NotEmpty(checkNodeInfo.EncryptionPublicKeyBytes)
						assert.NotEmpty(checkNodeInfo.ServerEncryptionPrivateKeyBytes)
					} else {
						require.NotNil(checkNodeInfo.MlkemParameters)
						assert.NotEmpty(checkNodeInfo.MlkemParameters.SharedKey)
						assert.NotEmpty(checkNodeInfo.MlkemParameters.Ciphertext)
					}
					assert.NotNil(checkNodeInfo.RegistrationChallenge)
				})
			}
		})
	}
}

func TestAuthorizeNodeCommon_DuplicateStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, kt := range nodetesting.TestKeyTypeVariants() {
		t.Run(kt.Name, func(t *testing.T) {
			t.Parallel()

			storage, err := testing2.New(ctx)
			require.NoError(t, err)

			_, err = rotation.RotateRootCertificates(ctx, storage)
			require.NoError(t, err)

			// This happens on the node
			nodeCreds, err := types.NewNodeCredentials(ctx, storage, kt.Opts...)
			require.NoError(t, err)
			fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
			require.NoError(t, err)
			keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
			require.NoError(t, err)

			fetchInfo, _ := registration.ValidateFetchRequestCommon(ctx, storage, fetchReq)
			_, err = registration.AuthorizeNodeCommon(ctx, storage, fetchInfo)
			require.NoError(t, err)

			checkNodeInfo := &types.NodeInformation{Id: keyId}
			require.NoError(t, storage.Load(ctx, checkNodeInfo))
			require.NotNil(t, checkNodeInfo)
			assert.Equal(t, keyId, checkNodeInfo.Id)
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
			assert.Equal(t, kt.KeyType, checkNodeInfo.EncryptionPublicKeyType)
			assert.Equal(t, kt.KeyType, checkNodeInfo.ServerEncryptionPrivateKeyType)
			if kt.KeyType == types.KEYTYPE_X25519 {
				assert.NotEmpty(t, checkNodeInfo.EncryptionPublicKeyBytes)
				assert.NotEmpty(t, checkNodeInfo.ServerEncryptionPrivateKeyBytes)
			} else {
				require.NotNil(t, checkNodeInfo.MlkemParameters)
				assert.NotEmpty(t, checkNodeInfo.MlkemParameters.SharedKey)
			}

			// Simulate a withWrapper case where we might hit authorizeNodeCommon a second time
			returnedNodeInfo, err := registration.AuthorizeNodeCommon(ctx, storage, fetchInfo)
			require.NoError(t, err)
			require.Equal(t, checkNodeInfo, returnedNodeInfo)
			if kt.KeyType == types.KEYTYPE_X25519 {
				require.Equal(t, checkNodeInfo.ServerEncryptionPrivateKeyBytes, returnedNodeInfo.ServerEncryptionPrivateKeyBytes)
			} else {
				require.NotNil(t, checkNodeInfo.MlkemParameters)
				require.Equal(t, checkNodeInfo.MlkemParameters.SharedKey, returnedNodeInfo.MlkemParameters.SharedKey)
			}
		})
	}
}
