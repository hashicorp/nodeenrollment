package types_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/google/go-cmp/cmp"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestNodeInformation_StoreLoad(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	storage, err := file.New(ctx)
	require.NoError(t, err)
	t.Cleanup(storage.Cleanup)

	// Generate a suitable root
	privKey := make([]byte, curve25519.ScalarSize)
	n, err := rand.Read(privKey)
	require.NoError(t, err)
	require.Equal(t, n, curve25519.ScalarSize)

	state, err := structpb.NewStruct(map[string]any{"foo": "bar"})
	require.NoError(t, err)

	nodeInfo := &types.NodeInformation{
		ServerEncryptionPrivateKeyBytes: privKey,
		State:                           state,
	}

	// We don't care about this key, just need something valid for the marshal function
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	nodeInfo.CertificatePublicKeyPkix, err = x509.MarshalPKIXPublicKey(pubKey)
	require.NoError(t, err)

	nodeInfo.Id, err = nodeenrollment.KeyIdFromPkix(nodeInfo.CertificatePublicKeyPkix)
	require.NoError(t, err)
	nodeInfo.RegistrationNonce = pubKey

	validWrapper := aead.TestWrapper(t)
	invalidWrapper := aead.TestWrapper(t)

	tests := []struct {
		name string
		// Return a modified node information and a "want err contains" string
		storeSetupFn func(*types.NodeInformation) (*types.NodeInformation, string)
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
			storeSetupFn: func(nodeInfo *types.NodeInformation) (*types.NodeInformation, string) {
				nodeInfo.Id = ""
				return nodeInfo, "missing id"
			},
		},
		{
			name: "store-invalid-nil-storage",
			storeSetupFn: func(nodeInfo *types.NodeInformation) (*types.NodeInformation, string) {
				return nodeInfo, "storage is nil"
			},
			storeStorageNil: true,
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
			loadWantErrContains: nodeenrollment.ErrNotFound.Error(),
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
			n := nodeInfo
			if !tt.skipStorage {
				var storeStorage nodeenrollment.Storage
				if !tt.storeStorageNil {
					storeStorage = storage
				}
				var wantErrContains string
				if tt.storeSetupFn != nil {
					n, wantErrContains = tt.storeSetupFn(proto.Clone(n).(*types.NodeInformation))
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
				testNodeInfo := &types.NodeInformation{Id: nodeInfo.Id}
				require.NoError(storage.Load(ctx, testNodeInfo))
				if tt.storeWrapper != nil {
					assert.EqualValues(pubKey, testNodeInfo.RegistrationNonce)
					assert.NotEqualValues(nodeInfo.ServerEncryptionPrivateKeyBytes, testNodeInfo.ServerEncryptionPrivateKeyBytes)
					// This should be set in storage but not modified in the original struct
					assert.NotEmpty(testNodeInfo.WrappingKeyId)
					assert.Empty(n.WrappingKeyId)
				} else {
					assert.EqualValues(pubKey, testNodeInfo.RegistrationNonce)
					assert.EqualValues(nodeInfo.ServerEncryptionPrivateKeyBytes, testNodeInfo.ServerEncryptionPrivateKeyBytes)
				}
			}

			loadId := nodeInfo.Id
			if tt.loadIdOverride != nil {
				loadId = string(tt.loadIdOverride)
			}
			var loadStorage nodeenrollment.Storage
			if !tt.loadStorageNil {
				loadStorage = storage
			}
			loaded, err := types.LoadNodeInformation(ctx, loadStorage, loadId, nodeenrollment.WithWrapper(tt.loadWrapper))
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

func TestNodeInformation_X25519(t *testing.T) {
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

	nodeInfo := &types.NodeInformation{
		ServerEncryptionPrivateKeyBytes: privKey,
		ServerEncryptionPrivateKeyType:  types.KEYTYPE_X25519,
		EncryptionPublicKeyBytes:        pubKey,
		EncryptionPublicKeyType:         types.KEYTYPE_X25519,
		CertificatePublicKeyPkix:        pubKeyPkix,
	}

	tests := []struct {
		name string
		// Return a modified node information and a "want err contains" string
		setupFn func(*types.NodeInformation) (*types.NodeInformation, string)
	}{
		{
			name: "invalid-nil",
			setupFn: func(nodeInfo *types.NodeInformation) (*types.NodeInformation, string) {
				return nil, "is empty"
			},
		},
		{
			name: "invalid-no-privkey-bytes",
			setupFn: func(nodeInfo *types.NodeInformation) (*types.NodeInformation, string) {
				nodeInfo.ServerEncryptionPrivateKeyBytes = nil
				return nodeInfo, "private key bytes is empty"
			},
		},
		{
			name: "invalid-bad-privkey-type",
			setupFn: func(nodeInfo *types.NodeInformation) (*types.NodeInformation, string) {
				nodeInfo.ServerEncryptionPrivateKeyType = types.KEYTYPE_ED25519
				return nodeInfo, "private key type is not known"
			},
		},
		{
			name: "invalid-no-pubkey-bytes",
			setupFn: func(nodeInfo *types.NodeInformation) (*types.NodeInformation, string) {
				nodeInfo.EncryptionPublicKeyBytes = nil
				return nodeInfo, "public key bytes is empty"
			},
		},
		{
			name: "invalid-bad-pubkey-type",
			setupFn: func(nodeInfo *types.NodeInformation) (*types.NodeInformation, string) {
				nodeInfo.EncryptionPublicKeyType = types.KEYTYPE_ED25519
				return nodeInfo, "public key type is not known"
			},
		},
		{
			name: "valid",
			setupFn: func(nodeInfo *types.NodeInformation) (*types.NodeInformation, string) {
				return nodeInfo, ""
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			n := nodeInfo
			var wantErrContains string
			if tt.setupFn != nil {
				n, wantErrContains = tt.setupFn(proto.Clone(n).(*types.NodeInformation))
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

	// Generate a suitable root
	privKey3 := make([]byte, curve25519.ScalarSize)
	n2, err := rand.Read(privKey3)
	require.NoError(t, err)
	require.Equal(t, n2, curve25519.ScalarSize)

	privKey4 := make([]byte, curve25519.ScalarSize)
	n2, err = rand.Read(privKey)
	require.NoError(t, err)
	require.Equal(t, n2, curve25519.ScalarSize)
	pubKey2, err := curve25519.X25519(privKey4, curve25519.Basepoint)
	require.NoError(t, err)
	certPubKey2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKeyPkix2, err := x509.MarshalPKIXPublicKey(certPubKey2)
	require.NoError(t, err)

	nodeInfo2 := &types.NodeInformation{
		ServerEncryptionPrivateKeyBytes: privKey3,
		ServerEncryptionPrivateKeyType:  types.KEYTYPE_X25519,
		EncryptionPublicKeyBytes:        pubKey2,
		EncryptionPublicKeyType:         types.KEYTYPE_X25519,
		CertificatePublicKeyPkix:        pubKeyPkix2,
	}

	oldKeyId, _, _ := nodeInfo.X25519EncryptionKey()
	newKeyId, _, _ := nodeInfo2.X25519EncryptionKey()

	nodeInfo2.SetPreviousEncryptionKey(nodeInfo)
	tests2 := []struct {
		name         string
		previousInfo *types.NodeInformation
		wantErr      bool
	}{
		{
			name:    "empty-previous-creds",
			wantErr: true,
		},
		{
			name:         "valid",
			previousInfo: nodeInfo,
			wantErr:      false,
		},
	}
	for _, tt := range tests2 {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			n := nodeInfo2
			err := n.SetPreviousEncryptionKey(tt.previousInfo)
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
			_, oldCredKey, err := tt.previousInfo.X25519EncryptionKey()
			require.NoError(err)
			require.NotNil(pKey, oldCredKey)

			// Encrypt a message with prior key and ensure it can be decrypted
			message := &wrapping.BlobInfo{
				Ciphertext: []byte("foo"),
				Iv:         []byte("bar"),
				Hmac:       []byte("baz"),
			}
			encryptedMsg, err := nodeenrollment.EncryptMessage(context.Background(), message, nodeInfo)
			require.NoError(err)
			decryptedMsg := new(wrapping.BlobInfo)
			err = nodeenrollment.DecryptMessage(context.Background(), encryptedMsg, nodeInfo2, decryptedMsg)
			require.NoError(err)
			assert.Empty(cmp.Diff(message, decryptedMsg, protocmp.Transform()))
		})
	}
}
