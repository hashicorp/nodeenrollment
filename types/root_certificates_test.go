// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package types_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"testing"

	"github.com/google/go-cmp/cmp"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

func TestRootCertificates_StoreLoad(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	storage, err := file.New(ctx)
	require.NoError(t, err)
	t.Cleanup(storage.Cleanup)

	// Generate a suitable root
	_, privKey, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	privPkcs8, err := x509.MarshalPKCS8PrivateKey(privKey)
	require.NoError(t, err)

	state, err := structpb.NewStruct(map[string]any{"foo": "bar"})
	require.NoError(t, err)

	roots := &types.RootCertificates{
		Id: nodeenrollment.RootsMessageId,
		Current: &types.RootCertificate{
			Id:              string(nodeenrollment.CurrentId),
			PrivateKeyPkcs8: privPkcs8,
		},
		Next: &types.RootCertificate{
			Id:              string(nodeenrollment.NextId),
			PrivateKeyPkcs8: privPkcs8,
		},
		State: state,
	}

	validWrapper := aead.TestWrapper(t)
	invalidWrapper := aead.TestWrapper(t)

	tests := []struct {
		name string
		// Return a modified root certificate and a "want err contains" string
		storeSetupFn func(*types.RootCertificates) (*types.RootCertificates, string)
		// Flag to set storage to nil on store
		storeStorageNil bool
		// Skip storage to test load not finding root
		skipStorage bool
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
			storeSetupFn: func(roots *types.RootCertificates) (*types.RootCertificates, string) {
				roots.Current.Id = ""
				return roots, "missing id"
			},
		},
		{
			name: "store-invalid-bad-id",
			storeSetupFn: func(roots *types.RootCertificates) (*types.RootCertificates, string) {
				roots.Current.Id = "foo"
				return roots, "invalid root certificate id"
			},
		},
		{
			name: "store-invalid-nil-storage",
			storeSetupFn: func(roots *types.RootCertificates) (*types.RootCertificates, string) {
				return roots, "storage is nil"
			},
			storeStorageNil: true,
		},
		{
			name: "store-invalid-no-key",
			storeSetupFn: func(roots *types.RootCertificates) (*types.RootCertificates, string) {
				roots.Current.PrivateKeyPkcs8 = nil
				return roots, "no private key"
			},
		},
		{
			name: "load-valid",
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
		// NOTE: Leave these two last so we can test LoadRootCertificates
		// (should error in all other cases)
		{
			name: "store-valid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			r := roots
			if !tt.skipStorage {
				var storeStorage nodeenrollment.Storage
				if !tt.storeStorageNil {
					storeStorage = storage
				}
				var wantErrContains string
				if tt.storeSetupFn != nil {
					r, wantErrContains = tt.storeSetupFn(proto.Clone(r).(*types.RootCertificates))
				}
				err := r.Store(ctx, storeStorage, nodeenrollment.WithWrapper(tt.storeWrapper))
				switch wantErrContains {
				case "":
					require.NoError(err)
				default:
					require.Error(err)
					assert.Contains(err.Error(), wantErrContains)
					return
				}
			}

			// Do a check on the private key to ensure it's different
			if !tt.skipStorage {
				testRoots := &types.RootCertificates{Id: nodeenrollment.RootsMessageId}
				require.NoError(storage.Load(ctx, testRoots))
				if tt.storeWrapper != nil {
					assert.NotEqualValues(roots.Current.PrivateKeyPkcs8, testRoots.Current.PrivateKeyPkcs8)
					// This should be set in storage but not modified in the original struct
					assert.NotEmpty(testRoots.WrappingKeyId)
					assert.Empty(roots.WrappingKeyId)
				} else {
					assert.EqualValues(roots.Current.PrivateKeyPkcs8, testRoots.Current.PrivateKeyPkcs8)
				}
			}

			var loadStorage nodeenrollment.Storage
			if !tt.loadStorageNil {
				loadStorage = storage
			}
			loaded, err := types.LoadRootCertificates(ctx, loadStorage, nodeenrollment.WithWrapper(tt.loadWrapper))
			switch tt.loadWantErrContains {
			case "":
				require.NoError(err)
			default:
				require.Error(err)
				assert.Contains(err.Error(), tt.loadWantErrContains)
				return
			}

			assert.Empty(cmp.Diff(r, loaded, protocmp.Transform()))

			// Now test the multi-load function
			certs, err := types.LoadRootCertificates(ctx, loadStorage, nodeenrollment.WithWrapper(tt.loadWrapper))
			switch nodeenrollment.KnownId(r.Id) {
			case nodeenrollment.CurrentId:
				require.Error(err)
				assert.Contains(err.Error(), nodeenrollment.ErrNotFound.Error())
				assert.Nil(certs)
			default:
				require.NoError(err)
				require.NotNil(certs)
				assert.NotNil(certs.Current)
				assert.NotNil(certs.Next)
			}
		})
	}
}

func TestRootCertificate_SigningParams(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	storage, err := file.New(ctx)
	require.NoError(t, err)
	t.Cleanup(storage.Cleanup)

	roots, err := rotation.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)
	require.NotNil(t, roots)
	require.NotNil(t, roots.Current)

	tests := []struct {
		name string
		// Return a modified root certificate and a "want err contains" string
		setupFn func(*types.RootCertificate) (*types.RootCertificate, string)
	}{
		{
			name: "valid",
		},
		{
			name: "invalid-missing-private-key",
			setupFn: func(root *types.RootCertificate) (*types.RootCertificate, string) {
				root.PrivateKeyPkcs8 = nil
				return root, "no private key"
			},
		},
		{
			name: "invalid-bad-key-type",
			setupFn: func(root *types.RootCertificate) (*types.RootCertificate, string) {
				root.PrivateKeyType = types.KEYTYPE_X25519
				return root, "unsupported private key type"
			},
		},
		{
			name: "invalid-unspecified-key-type",
			setupFn: func(root *types.RootCertificate) (*types.RootCertificate, string) {
				root.PrivateKeyType = types.KEYTYPE_UNSPECIFIED
				return root, "information not found"
			},
		},
		{
			name: "invalid-corrupt-key",
			setupFn: func(root *types.RootCertificate) (*types.RootCertificate, string) {
				root.PrivateKeyPkcs8[10] = 'W'
				root.PrivateKeyPkcs8[20] = 'H'
				root.PrivateKeyPkcs8[30] = 'Y'
				return root, "error unmarshaling private key"
			},
		},
		{
			name: "invalid-no-certificate",
			setupFn: func(root *types.RootCertificate) (*types.RootCertificate, string) {
				root.CertificateDer = nil
				return root, "no certificate"
			},
		},
		{
			name: "invalid-corrupt-certificate",
			setupFn: func(root *types.RootCertificate) (*types.RootCertificate, string) {
				root.CertificateDer[10] = 'W'
				root.CertificateDer[20] = 'H'
				root.CertificateDer[30] = 'Y'
				return root, "error parsing certificate bytes"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			r := roots.Current
			var wantErrContains string
			if tt.setupFn != nil {
				r, wantErrContains = tt.setupFn(proto.Clone(r).(*types.RootCertificate))
			}
			cert, signer, err := r.SigningParams(ctx)
			switch wantErrContains {
			case "":
				require.NoError(err)
				assert.NotNil(signer)
				assert.NotNil(cert)
			default:
				require.Error(err)
				assert.Contains(err.Error(), wantErrContains)
			}
		})
	}
}
