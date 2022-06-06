package rotation

import (
	"context"
	"testing"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRotateNodeCredentials tests the node credential rotation function.
//
// NOTE: as this is mostly chaining together functions from elsewhere in the
// library, the tests are really designed to verify the inputs to this function.
// There is not exhaustive testing of the outputs of other functions as it's
// assumed the tests on those functions are sufficient.
func TestRotateNodeCredentials(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	storage, err := file.New(ctx)
	require.NoError(t, err)
	t.Cleanup(storage.Cleanup)

	// Ensure nil storage fails
	roots, err := RotateRootCertificates(ctx, storage)
	require.NoError(t, err)
	assert.NotNil(t, roots)

	// Generate and authorize original credentials
	require.NoError(t, err)
	currentNodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)
	req, err := currentNodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)
	currentNodeInfo, err := registration.AuthorizeNode(ctx, storage, req)
	require.NoError(t, err)
	fetchResp, err := registration.FetchNodeCredentials(ctx, storage, req)
	require.NoError(t, err)
	currentNodeCreds, err = currentNodeCreds.HandleFetchNodeCredentialsResponse(ctx, storage, fetchResp)
	require.NoError(t, err)
	currentKeyId, err := nodeenrollment.KeyIdFromPkix(currentNodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)

	standardRotateFunc := func(t *testing.T, currentNodeCreds *types.NodeCredentials) (*types.NodeCredentials, *types.RotateNodeCredentialsRequest, error) {
		newNodeCreds, err := types.NewNodeCredentials(
			ctx,
			storage,
			nodeenrollment.WithSkipStorage(true),
		)
		require.NoError(t, err)

		// Get a signed request from the new credentials
		fetchReq, err := newNodeCreds.CreateFetchNodeCredentialsRequest(ctx)
		require.NoError(t, err)

		// Encrypt the values to the server
		encFetchReq, err := nodeenrollment.EncryptMessage(ctx, currentKeyId, fetchReq, currentNodeCreds)
		require.NoError(t, err)

		req := &types.RotateNodeCredentialsRequest{
			CertificatePublicKeyPkix:             currentNodeCreds.CertificatePublicKeyPkix,
			EncryptedFetchNodeCredentialsRequest: encFetchReq,
		}

		return newNodeCreds, req, nil
	}

	tests := []struct {
		name string
		// Return a modified node information and a "want err contains" string
		setupFn    func(*testing.T, *types.NodeCredentials) (*types.NodeCredentials, *types.RotateNodeCredentialsRequest, string)
		nilStorage bool
	}{
		{
			name: "invalid-nil-request",
			setupFn: func(t *testing.T, nodeCreds *types.NodeCredentials) (*types.NodeCredentials, *types.RotateNodeCredentialsRequest, string) {
				return nil, nil, "nil request"
			},
		},
		{
			name: "invalid-nil-storage",
			setupFn: func(t *testing.T, nodeCreds *types.NodeCredentials) (*types.NodeCredentials, *types.RotateNodeCredentialsRequest, string) {
				newNodeCreds, req, err := standardRotateFunc(t, nodeCreds)
				require.NoError(t, err)
				return newNodeCreds, req, "nil storage"
			},
			nilStorage: true,
		},
		{
			name: "invalid-nil-public-key",
			setupFn: func(t *testing.T, nodeCreds *types.NodeCredentials) (*types.NodeCredentials, *types.RotateNodeCredentialsRequest, string) {
				newNodeCreds, req, err := standardRotateFunc(t, nodeCreds)
				require.NoError(t, err)
				req.CertificatePublicKeyPkix = nil
				return newNodeCreds, req, "nil certificate public key"
			},
		},
		{
			name: "invalid-nil-storage",
			setupFn: func(t *testing.T, nodeCreds *types.NodeCredentials) (*types.NodeCredentials, *types.RotateNodeCredentialsRequest, string) {
				newNodeCreds, req, err := standardRotateFunc(t, nodeCreds)
				require.NoError(t, err)
				req.EncryptedFetchNodeCredentialsRequest = nil
				return newNodeCreds, req, "nil encrypted fetch"
			},
		},
		{
			name: "no-current-creds",
			setupFn: func(t *testing.T, nodeCreds *types.NodeCredentials) (*types.NodeCredentials, *types.RotateNodeCredentialsRequest, string) {
				newNodeCreds, req, err := standardRotateFunc(t, nodeCreds)
				require.NoError(t, err)
				require.NoError(t, storage.Remove(ctx, &types.NodeInformation{Id: currentNodeInfo.Id}))
				return newNodeCreds, req, nodeenrollment.ErrNotFound.Error()
			},
		},
		{
			name: "valid",
			setupFn: func(t *testing.T, nodeCreds *types.NodeCredentials) (*types.NodeCredentials, *types.RotateNodeCredentialsRequest, string) {
				newNodeCreds, req, err := standardRotateFunc(t, nodeCreds)
				require.NoError(t, err)
				return newNodeCreds, req, ""
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			// Ensure this is available at the start of each test as some remove it
			require.NoError(currentNodeInfo.Store(ctx, storage))

			var req *types.RotateNodeCredentialsRequest
			var newNodeCreds *types.NodeCredentials
			var wantErrContains string
			if tt.setupFn != nil {
				newNodeCreds, req, wantErrContains = tt.setupFn(t, currentNodeCreds)
			}

			testStorage := storage
			if tt.nilStorage {
				testStorage = nil
			}

			resp, err := RotateNodeCredentials(ctx, testStorage, req)
			if wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), wantErrContains)
				return
			}

			require.NoError(err)
			assert.NotEmpty(resp)
			assert.NotEmpty(resp.EncryptedFetchNodeCredentialsResponse)

			fetchResp := new(types.FetchNodeCredentialsResponse)
			require.NoError(nodeenrollment.DecryptMessage(
				ctx,
				currentKeyId,
				resp.EncryptedFetchNodeCredentialsResponse,
				currentNodeCreds,
				fetchResp,
			))

			_, err = newNodeCreds.HandleFetchNodeCredentialsResponse(ctx, storage, fetchResp)
			require.NoError(err)
		})
	}
}
