// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: MPL-2.0

package rotation

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/protocol"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/storage/inmem"
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

	// setupInitialCreds initializes fresh in-memory storage with roots and a
	// fully-registered node using the given encryption key type.
	setupInitialCreds := func(t *testing.T, keyType types.KEYTYPE) (nodeenrollment.Storage, *types.NodeInformation, *types.NodeCredentials) {
		t.Helper()
		storage, err := inmem.New(ctx)
		require.NoError(t, err)
		roots, err := RotateRootCertificates(ctx, storage)
		require.NoError(t, err)
		require.NotNil(t, roots)
		nodeCreds, err := types.NewNodeCredentials(ctx, storage, nodeenrollment.WithEncryptionPrivateKeyType(uint(keyType)))
		require.NoError(t, err)
		req, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
		require.NoError(t, err)
		nodeInfo, err := registration.AuthorizeNode(ctx, storage, req)
		require.NoError(t, err)
		req, err = nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
		require.NoError(t, err)
		fetchResp, err := registration.FetchNodeCredentials(ctx, storage, req)
		require.NoError(t, err)
		nodeCreds, err = nodeCreds.HandleFetchNodeCredentialsResponse(ctx, storage, fetchResp)
		require.NoError(t, err)
		return storage, nodeInfo, nodeCreds
	}

	// doRotate creates new node credentials with the given key type, encrypts
	// a fetch request signed by currentNodeCreds, calls RotateNodeCredentials,
	// and handles the response. It returns the new node credentials ready for
	// the next operation.
	doRotate := func(t *testing.T, storage nodeenrollment.Storage, currentNodeCreds *types.NodeCredentials, newKeyType types.KEYTYPE) *types.NodeCredentials {
		t.Helper()
		newNodeCreds, err := types.NewNodeCredentials(ctx, storage,
			nodeenrollment.WithSkipStorage(true),
			nodeenrollment.WithEncryptionPrivateKeyType(uint(newKeyType)),
		)
		require.NoError(t, err)
		fetchReq, err := newNodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
		require.NoError(t, err)
		encFetchReq, err := nodeenrollment.EncryptMessage(ctx, fetchReq, currentNodeCreds)
		require.NoError(t, err)
		rotReq := &types.RotateNodeCredentialsRequest{
			CertificatePublicKeyPkix:             currentNodeCreds.CertificatePublicKeyPkix,
			EncryptedFetchNodeCredentialsRequest: encFetchReq,
		}
		resp, err := RotateNodeCredentials(ctx, storage, rotReq)
		require.NoError(t, err)
		require.NotEmpty(t, resp)
		require.NotEmpty(t, resp.EncryptedFetchNodeCredentialsResponse)
		fetchResp := new(types.FetchNodeCredentialsResponse)
		require.NoError(t, nodeenrollment.DecryptMessage(ctx, resp.EncryptedFetchNodeCredentialsResponse, currentNodeCreds, fetchResp))
		newNodeCreds, err = newNodeCreds.HandleFetchNodeCredentialsResponse(ctx, storage, fetchResp)
		require.NoError(t, err)
		return newNodeCreds
	}

	// Error cases use a shared X25519 setup; they run sequentially.
	t.Run("error-cases", func(t *testing.T) {
		storage, currentNodeInfo, currentNodeCreds := setupInitialCreds(t, types.KEYTYPE_X25519)

		// buildValidRotateReq creates a well-formed rotation request encrypted
		// with nodeCreds, used as a baseline that error-case setup fns can
		// then corrupt in the desired way.
		buildValidRotateReq := func(t *testing.T, nodeCreds *types.NodeCredentials) *types.RotateNodeCredentialsRequest {
			t.Helper()
			newNodeCreds, err := types.NewNodeCredentials(ctx, storage,
				nodeenrollment.WithSkipStorage(true),
				nodeenrollment.WithEncryptionPrivateKeyType(uint(types.KEYTYPE_X25519)),
			)
			require.NoError(t, err)
			fetchReq, err := newNodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
			require.NoError(t, err)
			encFetchReq, err := nodeenrollment.EncryptMessage(ctx, fetchReq, nodeCreds)
			require.NoError(t, err)
			return &types.RotateNodeCredentialsRequest{
				CertificatePublicKeyPkix:             nodeCreds.CertificatePublicKeyPkix,
				EncryptedFetchNodeCredentialsRequest: encFetchReq,
			}
		}

		tests := []struct {
			name       string
			setupFn    func(*testing.T, *types.NodeCredentials) (*types.RotateNodeCredentialsRequest, string)
			nilStorage bool
		}{
			{
				name: "nil-request",
				setupFn: func(t *testing.T, _ *types.NodeCredentials) (*types.RotateNodeCredentialsRequest, string) {
					return nil, "nil request"
				},
			},
			{
				name: "nil-storage",
				setupFn: func(t *testing.T, nodeCreds *types.NodeCredentials) (*types.RotateNodeCredentialsRequest, string) {
					return buildValidRotateReq(t, nodeCreds), "nil storage"
				},
				nilStorage: true,
			},
			{
				name: "nil-public-key",
				setupFn: func(t *testing.T, nodeCreds *types.NodeCredentials) (*types.RotateNodeCredentialsRequest, string) {
					req := buildValidRotateReq(t, nodeCreds)
					req.CertificatePublicKeyPkix = nil
					return req, "nil certificate public key"
				},
			},
			{
				name: "nil-encrypted-fetch",
				setupFn: func(t *testing.T, nodeCreds *types.NodeCredentials) (*types.RotateNodeCredentialsRequest, string) {
					req := buildValidRotateReq(t, nodeCreds)
					req.EncryptedFetchNodeCredentialsRequest = nil
					return req, "nil encrypted fetch"
				},
			},
			{
				name: "no-current-creds",
				setupFn: func(t *testing.T, nodeCreds *types.NodeCredentials) (*types.RotateNodeCredentialsRequest, string) {
					req := buildValidRotateReq(t, nodeCreds)
					require.NoError(t, storage.Remove(ctx, &types.NodeInformation{Id: currentNodeInfo.Id}))
					return req, nodeenrollment.ErrNotFound.Error()
				},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				require, assert := require.New(t), assert.New(t)

				// Ensure the node information is present at the start of each
				// subtest, as some cases remove it.
				require.NoError(currentNodeInfo.Store(ctx, storage))

				var req *types.RotateNodeCredentialsRequest
				var wantErrContains string
				if tt.setupFn != nil {
					req, wantErrContains = tt.setupFn(t, currentNodeCreds)
				}

				testStorage := storage
				if tt.nilStorage {
					testStorage = nil
				}

				_, err := RotateNodeCredentials(ctx, testStorage, req)
				require.Error(err)
				assert.Contains(err.Error(), wantErrContains)
			})
		}
	})

	// verifyCanConnect starts a fresh InterceptingListener and verifies that the
	// node credentials currently stored in storage allow a successful Dial.
	verifyCanConnect := func(t *testing.T, storage nodeenrollment.Storage) {
		t.Helper()
		baseLn, err := net.Listen("tcp4", "127.0.0.1:0")
		require.NoError(t, err)
		listener, err := protocol.NewInterceptingListener(&protocol.InterceptingListenerConfiguration{
			Context:      ctx,
			Storage:      storage,
			BaseListener: baseLn,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = listener.Close() })

		type serverResult struct {
			conn net.Conn
			err  error
		}
		results := make(chan serverResult, 1)
		go func() {
			conn, err := listener.Accept()
			results <- serverResult{conn, err}
		}()

		// Dial performs the auth TLS handshake; a non-nil error means the
		// stored credentials are not accepted by the server.
		clientConn, err := protocol.Dial(ctx, storage, listener.Addr().String())
		require.NoError(t, err, "node should be able to connect to server after rotation")
		_ = clientConn.Close()

		// By the time Dial returns the server's Accept has already returned
		// (it starts the handshake asynchronously), but we wait up to 5s to
		// ensure we don't race the goroutine.
		select {
		case r := <-results:
			require.NoError(t, r.err, "server Accept should succeed after rotation")
			if r.conn != nil {
				_ = r.conn.Close()
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for server Accept to return")
		}
	}

	// Valid rotation scenarios each use their own isolated storage so they can
	// run in parallel. Each scenario performs two sequential rotations.
	t.Run("valid-rotation-scenarios", func(t *testing.T) {
		tests := []struct {
			name           string
			initialKeyType types.KEYTYPE
			firstKeyType   types.KEYTYPE
			secondKeyType  types.KEYTYPE
		}{
			{
				name:           "x25519-to-x25519-to-x25519",
				initialKeyType: types.KEYTYPE_X25519,
				firstKeyType:   types.KEYTYPE_X25519,
				secondKeyType:  types.KEYTYPE_X25519,
			},
			{
				name:           "x25519-to-mlkem-to-mlkem",
				initialKeyType: types.KEYTYPE_X25519,
				firstKeyType:   types.KEYTYPE_MLKEM1024,
				secondKeyType:  types.KEYTYPE_MLKEM1024,
			},
			{
				name:           "x25519-to-mlkem-to-x25519",
				initialKeyType: types.KEYTYPE_X25519,
				firstKeyType:   types.KEYTYPE_MLKEM1024,
				secondKeyType:  types.KEYTYPE_X25519,
			},
			{
				name:           "mlkem-to-mlkem-to-mlkem",
				initialKeyType: types.KEYTYPE_MLKEM1024,
				firstKeyType:   types.KEYTYPE_MLKEM1024,
				secondKeyType:  types.KEYTYPE_MLKEM1024,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				storage, _, nodeCreds := setupInitialCreds(t, tt.initialKeyType)
				verifyCanConnect(t, storage)
				nodeCreds = doRotate(t, storage, nodeCreds, tt.firstKeyType)
				verifyCanConnect(t, storage)
				doRotate(t, storage, nodeCreds, tt.secondKeyType)
				verifyCanConnect(t, storage)
			})
		}
	})
}
