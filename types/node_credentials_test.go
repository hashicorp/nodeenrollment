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
)

func TestNodeCredentials_StoreLoad(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	storage, err := file.NewFileStorage(ctx)
	require.NoError(t, err)
	t.Cleanup(storage.Cleanup)

	// Generate a suitable root
	privKey := make([]byte, curve25519.ScalarSize)
	n, err := rand.Read(privKey)
	require.NoError(t, err)
	require.Equal(t, n, curve25519.ScalarSize)

	nodeCreds := &types.NodeCredentials{
		EncryptionPrivateKeyBytes: privKey,
	}

	// We don't care about this key, just need something valid for the marshal function
	pubKey, signingKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	nodeCreds.CertificatePublicKeyPkix, err = x509.MarshalPKIXPublicKey(pubKey)
	require.NoError(t, err)
	nodeCreds.CertificatePrivateKeyPkcs8, err = x509.MarshalPKCS8PrivateKey(signingKey)
	require.NoError(t, err)

	nodeCreds.Id, err = nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
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
				return nodeCreds, "no enryption private key"
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
			name:                "invalid-no-store-wrapping",
			loadWrapper:         validWrapper,
			loadWantErrContains: "no wrapping key id",
		},
		{
			name:                "no-load-wrapping",
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
					if tt.storeWrapper != nil {
						require.NotEmpty(n.WrappingKeyId)
						// Now that we've validated it was set, remove the wrapping
						// ID set on store as it's informational only and messes up
						// the compare later
						n.WrappingKeyId = ""
					}
				default:
					require.Error(err)
					assert.Contains(err.Error(), wantErrContains)
					return
				}
			}

			// Do a check on the registration nonce to ensure it's different
			if !tt.skipStorage {
				testnodeCreds := &types.NodeCredentials{Id: nodeCreds.Id}
				require.NoError(storage.Load(ctx, testnodeCreds))
				if tt.storeWrapper != nil {
					assert.NotEqualValues(pubKey, testnodeCreds.RegistrationNonce)
					assert.NotEqualValues(nodeCreds.EncryptionPrivateKeyBytes, testnodeCreds.EncryptionPrivateKeyBytes)
					assert.NotEqualValues(nodeCreds.CertificatePrivateKeyPkcs8, testnodeCreds.CertificatePrivateKeyPkcs8)
				} else {
					assert.EqualValues(pubKey, testnodeCreds.RegistrationNonce)
					assert.EqualValues(nodeCreds.EncryptionPrivateKeyBytes, testnodeCreds.EncryptionPrivateKeyBytes)
					assert.EqualValues(nodeCreds.CertificatePrivateKeyPkcs8, testnodeCreds.CertificatePrivateKeyPkcs8)
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

	nodeCreds := &types.NodeCredentials{
		EncryptionPrivateKeyBytes:      privKey,
		EncryptionPrivateKeyType:       types.KEYTYPE_KEYTYPE_X25519,
		ServerEncryptionPublicKeyBytes: pubKey,
		ServerEncryptionPublicKeyType:  types.KEYTYPE_KEYTYPE_X25519,
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
				nodeCreds.EncryptionPrivateKeyType = types.KEYTYPE_KEYTYPE_ED25519
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
				nodeCreds.ServerEncryptionPublicKeyType = types.KEYTYPE_KEYTYPE_ED25519
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
			out, err := n.X25519EncryptionKey()
			if wantErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), wantErrContains)
			} else {
				require.NoError(err)
				assert.NotEmpty(out)
			}
		})
	}
}
