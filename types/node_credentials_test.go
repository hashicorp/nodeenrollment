// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package types_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/storage/inmem"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

func TestNodeCredentials_StoreLoad(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	storage, err := inmem.New(ctx)
	require.NoError(t, err)

	// Generate a suitable root
	privKey := make([]byte, curve25519.ScalarSize)
	n, err := rand.Read(privKey)
	require.NoError(t, err)
	require.Equal(t, n, curve25519.ScalarSize)

	state, err := structpb.NewStruct(map[string]any{"foo": "bar"})
	require.NoError(t, err)

	nodeCreds := &types.NodeCredentials{
		Id:                        string(nodeenrollment.CurrentId),
		EncryptionPrivateKeyBytes: privKey,
		State:                     state,
	}

	// We don't care about this key, just need something valid for the marshal function
	pubKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	nodeCreds.CertificatePublicKeyPkix, err = x509.MarshalPKIXPublicKey(pubKey)
	require.NoError(t, err)
	nodeCreds.CertificatePrivateKeyPkcs8, err = x509.MarshalPKCS8PrivateKey(signingKey)
	require.NoError(t, err)
	nodeCreds.RegistrationNonce = pubKey

	validWrapper := aead.TestWrapper(t)
	invalidWrapper := aead.TestWrapper(t)

	tests := []struct {
		name string
		// Return a modified node information and a "want err contains" string
		storeSetupFn func(*types.NodeCredentials) (*types.NodeCredentials, string)
		// Flag to set storage to nil on store
		storeStorageNil bool
		// Skip storage to test load not finding node info
		skipStorage bool
		// Overrides the default id to load
		loadIdOverride []byte
		// Flag to set storage to nil on load
		loadStorageNil bool
		// Error to find on load
		loadWantErrContains string
		// The wrapper to use on store
		storeWrapper wrapping.Wrapper
		// The wrapper to use on load
		loadWrapper wrapping.Wrapper
	}{
		{
			// NOTE: leave this first so that storage from previous tests
			// doesn't interfere
			name:                "load-invalid-not-found",
			skipStorage:         true,
			loadWantErrContains: nodeenrollment.ErrNotFound.Error(),
		},
		{
			name: "store-invalid-no-id",
			storeSetupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				nodeCreds.Id = ""
				return nodeCreds, "missing id"
			},
		},
		{
			name: "store-invalid-nil-storage",
			storeSetupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				return nodeCreds, "storage is nil"
			},
			storeStorageNil: true,
		},
		{
			name: "store-invalid-no-pkix-key",
			storeSetupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				nodeCreds.CertificatePublicKeyPkix = nil
				return nodeCreds, "no certificate pkix public key"
			},
		},
		{
			name: "store-invalid-no-pkcs8-key",
			storeSetupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				nodeCreds.CertificatePrivateKeyPkcs8 = nil
				return nodeCreds, "no certificate pkcs8 private key"
			},
		},
		{
			name: "store-invalid-no-encryption-key",
			storeSetupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				nodeCreds.EncryptionPrivateKeyBytes = nil
				return nodeCreds, "no encryption private key"
			},
		},
		{
			name: "load-valid",
		},
		{
			name:                "load-invalid-no-id",
			loadIdOverride:      []byte(""),
			loadWantErrContains: "missing id",
		},
		{
			name:                "load-invalid-bad-id",
			loadIdOverride:      []byte("foo"),
			loadWantErrContains: "invalid node credentials id",
		},
		{
			name:                "load-invalid-nil-storage",
			loadStorageNil:      true,
			loadWantErrContains: "storage is nil",
		},
		{
			name:         "valid-with-wrapping",
			storeWrapper: validWrapper,
			loadWrapper:  validWrapper,
		},
		{
			name:        "valid-no-store-wrapping",
			loadWrapper: validWrapper,
		},
		{
			name:                "invalid-no-load-wrapping",
			storeWrapper:        validWrapper,
			loadWantErrContains: "wrapper not provided",
		},
		{
			name:                "invalid-mismatched-wrapping",
			storeWrapper:        validWrapper,
			loadWrapper:         invalidWrapper,
			loadWantErrContains: "message authentication failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			n := nodeCreds
			if !tt.skipStorage {
				var storeStorage nodeenrollment.Storage
				if !tt.storeStorageNil {
					storeStorage = storage
				}
				var wantErrContains string
				if tt.storeSetupFn != nil {
					n, wantErrContains = tt.storeSetupFn(proto.Clone(n).(*types.NodeCredentials))
				}
				err := n.Store(ctx, storeStorage, nodeenrollment.WithWrapper(tt.storeWrapper))
				switch wantErrContains {
				case "":
					require.NoError(err)
				default:
					require.Error(err)
					assert.Contains(err.Error(), wantErrContains)
					return
				}
			}

			// Do a check on the registration nonce to ensure it's different
			if !tt.skipStorage {
				testNodeCreds := &types.NodeCredentials{Id: nodeCreds.Id}
				require.NoError(storage.Load(ctx, testNodeCreds))
				if tt.storeWrapper != nil {
					assert.NotEqualValues(pubKey, testNodeCreds.RegistrationNonce)
					assert.NotEqualValues(nodeCreds.EncryptionPrivateKeyBytes, testNodeCreds.EncryptionPrivateKeyBytes)
					assert.NotEqualValues(nodeCreds.CertificatePrivateKeyPkcs8, testNodeCreds.CertificatePrivateKeyPkcs8)
					// This should be set in storage but not modified in the original struct
					assert.NotEmpty(testNodeCreds.WrappingKeyId)
					assert.Empty(n.WrappingKeyId)
				} else {
					assert.EqualValues(pubKey, testNodeCreds.RegistrationNonce)
					assert.EqualValues(nodeCreds.EncryptionPrivateKeyBytes, testNodeCreds.EncryptionPrivateKeyBytes)
					assert.EqualValues(nodeCreds.CertificatePrivateKeyPkcs8, testNodeCreds.CertificatePrivateKeyPkcs8)
				}
			}

			loadId := nodeCreds.Id
			if tt.loadIdOverride != nil {
				loadId = string(tt.loadIdOverride)
			}
			var loadStorage nodeenrollment.Storage
			if !tt.loadStorageNil {
				loadStorage = storage
			}
			loaded, err := types.LoadNodeCredentials(ctx, loadStorage, nodeenrollment.KnownId(loadId), nodeenrollment.WithWrapper(tt.loadWrapper))
			switch tt.loadWantErrContains {
			case "":
				require.NoError(err)
			default:
				require.Error(err)
				assert.Contains(err.Error(), tt.loadWantErrContains)
				return
			}

			assert.Empty(cmp.Diff(n, loaded, protocmp.Transform()))
		})
	}
}

func TestNodeCredentials_X25519(t *testing.T) {
	t.Parallel()

	// Generate a suitable root
	privKey := make([]byte, curve25519.ScalarSize)
	n, err := rand.Read(privKey)
	require.NoError(t, err)
	require.Equal(t, n, curve25519.ScalarSize)

	privKey2 := make([]byte, curve25519.ScalarSize)
	n, err = rand.Read(privKey2)
	require.NoError(t, err)
	require.Equal(t, n, curve25519.ScalarSize)
	pubKey, err := curve25519.X25519(privKey2, curve25519.Basepoint)
	require.NoError(t, err)
	certPubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyPkix, err := x509.MarshalPKIXPublicKey(certPubKey)
	require.NoError(t, err)

	nodeCreds := &types.NodeCredentials{
		EncryptionPrivateKeyBytes:      privKey,
		EncryptionPrivateKeyType:       types.KEYTYPE_X25519,
		ServerEncryptionPublicKeyBytes: pubKey,
		ServerEncryptionPublicKeyType:  types.KEYTYPE_X25519,
		CertificatePublicKeyPkix:       pubKeyPkix,
	}

	tests := []struct {
		name string
		// Return a modified node information and a "want err contains" string
		setupFn func(*types.NodeCredentials) (*types.NodeCredentials, string)
	}{
		{
			name: "invalid-nil",
			setupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				return nil, "is empty"
			},
		},
		{
			name: "invalid-no-privkey-bytes",
			setupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				nodeCreds.EncryptionPrivateKeyBytes = nil
				return nodeCreds, "private key bytes is empty"
			},
		},
		{
			name: "invalid-bad-privkey-type",
			setupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				nodeCreds.EncryptionPrivateKeyType = types.KEYTYPE_ED25519
				return nodeCreds, "private key type is not known"
			},
		},
		{
			name: "invalid-no-pubkey-bytes",
			setupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				nodeCreds.ServerEncryptionPublicKeyBytes = nil
				return nodeCreds, "public key bytes is empty"
			},
		},
		{
			name: "invalid-bad-pubkey-type",
			setupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				nodeCreds.ServerEncryptionPublicKeyType = types.KEYTYPE_ED25519
				return nodeCreds, "public key type is not known"
			},
		},
		{
			name: "valid",
			setupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				return nodeCreds, ""
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			n := nodeCreds
			var wantErrContains string
			if tt.setupFn != nil {
				n, wantErrContains = tt.setupFn(proto.Clone(n).(*types.NodeCredentials))
			}
			keyId, out, err := n.X25519EncryptionKey()
			if wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), wantErrContains)
			} else {
				require.NoError(err)
				assert.NotEmpty(out)
				assert.NotEmpty(keyId)
			}
		})
	}

	// Test setting and using prior encryption keys
	// Generate a suitable root
	privKey3 := make([]byte, curve25519.ScalarSize)
	n2, err := rand.Read(privKey3)
	require.NoError(t, err)
	require.Equal(t, n2, curve25519.ScalarSize)

	privKey4 := make([]byte, curve25519.ScalarSize)
	n2, err = rand.Read(privKey4)
	require.NoError(t, err)
	require.Equal(t, n2, curve25519.ScalarSize)
	pubKey2, err := curve25519.X25519(privKey4, curve25519.Basepoint)
	require.NoError(t, err)
	certPubKey2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyPkix2, err := x509.MarshalPKIXPublicKey(certPubKey2)
	require.NoError(t, err)

	nodeCreds2 := &types.NodeCredentials{
		EncryptionPrivateKeyBytes:      privKey3,
		EncryptionPrivateKeyType:       types.KEYTYPE_X25519,
		ServerEncryptionPublicKeyBytes: pubKey2,
		ServerEncryptionPublicKeyType:  types.KEYTYPE_X25519,
		CertificatePublicKeyPkix:       pubKeyPkix2,
	}
	oldKeyId, _, _ := nodeCreds.X25519EncryptionKey()
	newKeyId, _, _ := nodeCreds2.X25519EncryptionKey()

	nodeCreds2.SetPreviousEncryptionKey(nodeCreds)
	tests2 := []struct {
		name          string
		previousCreds *types.NodeCredentials
		wantErr       bool
	}{
		{
			name:    "empty-previous-creds",
			wantErr: true,
		},
		{
			name:          "valid",
			previousCreds: nodeCreds,
			wantErr:       false,
		},
	}
	for _, tt := range tests2 {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			n := nodeCreds2
			err := n.SetPreviousEncryptionKey(tt.previousCreds)
			if tt.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)
			keyId, xKey, err := n.X25519EncryptionKey()
			require.NoError(err)
			require.NotNil(xKey)
			require.Equal(keyId, newKeyId)
			require.NotEqual(keyId, oldKeyId)

			priorKeyId, pKey, err := n.PreviousX25519EncryptionKey()
			require.NoError(err)
			require.Equal(priorKeyId, oldKeyId)
			_, oldCredKey, err := tt.previousCreds.X25519EncryptionKey()
			require.NoError(err)
			require.NotNil(pKey, oldCredKey)

			// Encrypt a message with prior key and ensure it can be decrypted
			message := &wrapping.BlobInfo{
				Ciphertext: []byte("foo"),
				Iv:         []byte("bar"),
				Hmac:       []byte("baz"),
			}
			encryptedMsg, err := nodeenrollment.EncryptMessage(context.Background(), message, nodeCreds)
			require.NoError(err)
			decryptedMsg := new(wrapping.BlobInfo)
			err = nodeenrollment.DecryptMessage(context.Background(), encryptedMsg, nodeCreds2, decryptedMsg)
			require.NoError(err)
			assert.Empty(cmp.Diff(message, decryptedMsg, protocmp.Transform()))
		})
	}
}

func TestNodeCredentials_New(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(t, err)

	tests := []struct {
		name            string
		storage         nodeenrollment.Storage
		wantErrContains string
	}{
		{
			name:    "valid",
			storage: storage,
		},
		{
			name:            "nil-storage",
			wantErrContains: "storage is nil",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			n, err := types.NewNodeCredentials(ctx, tt.storage)
			if tt.wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrContains)
				return
			}
			require.NoError(err)
			assert.NotEmpty(n.CertificatePrivateKeyPkcs8)
			assert.Equal(types.KEYTYPE_ED25519, n.CertificatePrivateKeyType)
			assert.NotEmpty(n.CertificatePublicKeyPkix)
			assert.NotEmpty(n.EncryptionPrivateKeyBytes)
			assert.Equal(types.KEYTYPE_X25519, n.EncryptionPrivateKeyType)
			assert.NotEmpty(n.RegistrationNonce)

			testNodeCreds := &types.NodeCredentials{Id: n.Id}
			require.NoError(tt.storage.Load(ctx, testNodeCreds))
			assert.Empty(cmp.Diff(n, testNodeCreds, protocmp.Transform()))
		})
	}
}

func TestNodeCredentials_CreateFetchNodeCredentials(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(t, err)

	// Generate a suitable root
	nodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)

	tests := []struct {
		name string
		// Return a modified node information and a "want err contains" string
		setupFn func(*types.NodeCredentials) (*types.NodeCredentials, string)
	}{
		{
			name: "invalid-nil",
			setupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				return nil, "is nil"
			},
		},
		{
			name: "invalid-no-encryption-privkey-bytes",
			setupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				nodeCreds.EncryptionPrivateKeyBytes = nil
				return nodeCreds, "encryption private key is empty"
			},
		},
		{
			name: "invalid-no-certificate-pubkey-bytes",
			setupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				nodeCreds.CertificatePublicKeyPkix = nil
				return nodeCreds, "pkix public key is empty"
			},
		},
		{
			name: "invalid-no-certificate-privkey-bytes",
			setupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				nodeCreds.CertificatePrivateKeyPkcs8 = nil
				return nodeCreds, "pkcs8 private key is empty"
			},
		},
		{
			name: "invalid-no-registration-nonce",
			setupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				nodeCreds.RegistrationNonce = nil
				return nodeCreds, "registration nonce is empty"
			},
		},
		{
			name: "valid",
			setupFn: func(nodeCreds *types.NodeCredentials) (*types.NodeCredentials, string) {
				return nodeCreds, ""
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			n := nodeCreds
			var wantErrContains string
			if tt.setupFn != nil {
				n, wantErrContains = tt.setupFn(proto.Clone(n).(*types.NodeCredentials))
			}
			out, err := n.CreateFetchNodeCredentialsRequest(ctx)
			if wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), wantErrContains)
				return
			}

			require.NoError(err)
			assert.NotEmpty(out)

			// Now test the output
			require.NotEmpty(out.Bundle)
			require.NotEmpty(out.BundleSignature)

			var fetchInfo types.FetchNodeCredentialsInfo
			require.NoError(proto.Unmarshal(out.Bundle, &fetchInfo))

			require.NotEmpty(fetchInfo.CertificatePublicKeyPkix)
			assert.Equal(types.KEYTYPE_ED25519, fetchInfo.CertificatePublicKeyType)
			assert.Equal(nodeCreds.RegistrationNonce, fetchInfo.Nonce)
			assert.NotEmpty(fetchInfo.EncryptionPublicKeyBytes)
			assert.Equal(types.KEYTYPE_X25519, fetchInfo.EncryptionPublicKeyType)
			assert.Negative(time.Until(fetchInfo.NotBefore.AsTime()))
			assert.Positive(time.Until(fetchInfo.NotAfter.AsTime()))

			pubKey, err := x509.ParsePKIXPublicKey(fetchInfo.CertificatePublicKeyPkix)
			require.NoError(err)
			assert.True(ed25519.Verify(pubKey.(ed25519.PublicKey), out.Bundle, out.BundleSignature))
		})
	}
}

func TestNodeCredentials_HandleFetchNodeCredentialsResponse(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	storage, err := file.New(ctx)
	require.NoError(t, err)

	// Generate a suitable root
	nodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)

	// Create server keys
	serverPrivKey := make([]byte, curve25519.ScalarSize)
	n, err := rand.Read(serverPrivKey)
	require.NoError(t, err)
	require.Equal(t, n, curve25519.ScalarSize)
	serverPubKey, err := curve25519.X25519(serverPrivKey, curve25519.Basepoint)
	require.NoError(t, err)

	// Create node keys
	nodePubKey, err := curve25519.X25519(nodeCreds.EncryptionPrivateKeyBytes, curve25519.Basepoint)
	require.NoError(t, err)

	// Create and sign encrypted creds
	serverNodeCreds := &types.NodeCredentials{
		ServerEncryptionPublicKeyBytes: serverPubKey,
		ServerEncryptionPublicKeyType:  types.KEYTYPE_X25519,
		RegistrationNonce:              nodeCreds.RegistrationNonce,
		CertificateBundles: []*types.CertificateBundle{
			{
				CertificateDer:   []byte("cert"),
				CaCertificateDer: []byte("ca"),
			},
		},
	}
	nodeInfo := &types.NodeInformation{
		ServerEncryptionPrivateKeyBytes: serverPrivKey,
		ServerEncryptionPrivateKeyType:  types.KEYTYPE_X25519,
		EncryptionPublicKeyBytes:        nodePubKey,
		EncryptionPublicKeyType:         types.KEYTYPE_X25519,
		CertificatePublicKeyPkix:        nodeCreds.CertificatePublicKeyPkix,
	}
	encryptedCreds, err := nodeenrollment.EncryptMessage(ctx, serverNodeCreds, nodeInfo)
	require.NoError(t, err)

	fetchNodeCredsResp := &types.FetchNodeCredentialsResponse{
		ServerEncryptionPublicKeyBytes: serverPubKey,
		ServerEncryptionPublicKeyType:  types.KEYTYPE_X25519,
		EncryptedNodeCredentials:       encryptedCreds,
	}

	tests := []struct {
		name             string
		storage          nodeenrollment.Storage
		nodeCredsSetupFn func(*types.NodeCredentials) (*types.NodeCredentials, string)
		respSetupFn      func(*types.FetchNodeCredentialsResponse) (*types.FetchNodeCredentialsResponse, string)
		wantErrContains  string
	}{
		{
			name: "invalid-nodecreds-nil",
			nodeCredsSetupFn: func(in *types.NodeCredentials) (*types.NodeCredentials, string) {
				return nil, "node credentials is nil"
			},
			storage: storage,
		},
		{
			name: "invalid-resp-nil",
			respSetupFn: func(in *types.FetchNodeCredentialsResponse) (*types.FetchNodeCredentialsResponse, string) {
				return nil, "input is nil"
			},
			storage: storage,
		},
		{
			name: "invalid-resp-nil-creds",
			respSetupFn: func(in *types.FetchNodeCredentialsResponse) (*types.FetchNodeCredentialsResponse, string) {
				in.EncryptedNodeCredentials = nil
				return in, "input encrypted node credentials"
			},
			storage: storage,
		},
		{
			name: "invalid-resp-nil-server-pubkey-bytes",
			respSetupFn: func(in *types.FetchNodeCredentialsResponse) (*types.FetchNodeCredentialsResponse, string) {
				in.ServerEncryptionPublicKeyBytes = nil
				return in, "encryption public key bytes"
			},
			storage: storage,
		},
		{
			name: "invalid-resp-nil-server-pubkey-type",
			respSetupFn: func(in *types.FetchNodeCredentialsResponse) (*types.FetchNodeCredentialsResponse, string) {
				in.ServerEncryptionPublicKeyType = types.KEYTYPE_ED25519
				return in, "encryption public key type"
			},
			storage: storage,
		},
		{
			name:            "invalid-nil storage",
			wantErrContains: "nil storage",
		},
		{
			name: "invalid-resp-tampered-encryption",
			respSetupFn: func(in *types.FetchNodeCredentialsResponse) (*types.FetchNodeCredentialsResponse, string) {
				in.EncryptedNodeCredentials[10] = 'w'
				in.EncryptedNodeCredentials[20] = 'h'
				in.EncryptedNodeCredentials[30] = 'y'
				return in, "message authentication failed"
			},
			storage: storage,
		},
		{
			name:    "valid",
			storage: storage,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			n := nodeCreds
			var wantNodeCredsErrContains string
			if tt.nodeCredsSetupFn != nil {
				n, wantNodeCredsErrContains = tt.nodeCredsSetupFn(proto.Clone(nodeCreds).(*types.NodeCredentials))
			}

			f := fetchNodeCredsResp
			var wantFetchRespErrContains string
			if tt.respSetupFn != nil {
				f, wantFetchRespErrContains = tt.respSetupFn(proto.Clone(f).(*types.FetchNodeCredentialsResponse))
			}

			_, err = n.HandleFetchNodeCredentialsResponse(ctx, tt.storage, f)
			if tt.wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantErrContains)
				return
			}
			if wantNodeCredsErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), wantNodeCredsErrContains)
				return
			}
			if wantFetchRespErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), wantFetchRespErrContains)
				return
			}
			require.NoError(err)

			// Now validate the decrypted/post-decryption
			assert.Len(n.CertificateBundles, 1)
			assert.Empty(n.RegistrationNonce)
			assert.Equal(n.Id, string(nodeenrollment.CurrentId))
		})
	}
}
