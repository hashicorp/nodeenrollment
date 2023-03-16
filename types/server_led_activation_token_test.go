// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package types_test

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/storage/inmem"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	structpb "google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestServerLedActivationToken_StoreLoad(t *testing.T) {
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

	var (
		tokenEntry = new(types.ServerLedActivationToken)
		tokenNonce = new(types.ServerLedActivationTokenNonce)
	)

	tokenNonce.Nonce = make([]byte, nodeenrollment.NonceSize)
	num, err := rand.Read(tokenNonce.Nonce)
	require.NoError(t, err)
	require.Equal(t, nodeenrollment.NonceSize, num)
	tokenNonce.HmacKeyBytes = make([]byte, 32)
	num, err = rand.Read(tokenNonce.HmacKeyBytes)
	require.NoError(t, err)
	require.Equal(t, 32, num)
	hm := hmac.New(sha256.New, tokenNonce.HmacKeyBytes)
	idBytes := hm.Sum(tokenNonce.Nonce)
	tokenEntry.Id = base58.FastBase58Encoding(idBytes)

	now := time.Now()
	tokenEntry.CreationTime = timestamppb.New(now)
	tokenEntry.State = state

	validWrapper := aead.TestWrapper(t)
	invalidWrapper := aead.TestWrapper(t)

	tests := []struct {
		name string
		// Return a modified node information and a "want err contains" string
		storeSetupFn func(*types.ServerLedActivationToken) (*types.ServerLedActivationToken, string)
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
			storeSetupFn: func(nodeInfo *types.ServerLedActivationToken) (*types.ServerLedActivationToken, string) {
				nodeInfo.Id = ""
				return nodeInfo, "missing id"
			},
		},
		{
			name: "store-invalid-nil-storage",
			storeSetupFn: func(nodeInfo *types.ServerLedActivationToken) (*types.ServerLedActivationToken, string) {
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
			s := tokenEntry
			if !tt.skipStorage {
				var storeStorage nodeenrollment.Storage
				if !tt.storeStorageNil {
					storeStorage = storage
				}
				var wantErrContains string
				if tt.storeSetupFn != nil {
					s, wantErrContains = tt.storeSetupFn(proto.Clone(s).(*types.ServerLedActivationToken))
				}
				err := s.Store(ctx, storeStorage, nodeenrollment.WithWrapper(tt.storeWrapper))
				switch wantErrContains {
				case "":
					require.NoError(err)
					assert.NotEmpty(s.CreationTimeMarshaled)
				default:
					require.Error(err)
					assert.Contains(err.Error(), wantErrContains)
					return
				}
			}

			// Do a check on the registration nonce to ensure it's different
			if !tt.skipStorage {
				testTokenEntry := &types.ServerLedActivationToken{Id: tokenEntry.Id}
				require.NoError(storage.Load(ctx, testTokenEntry))
				if tt.storeWrapper != nil {
					assert.NotEqualValues(s.CreationTimeMarshaled, testTokenEntry.CreationTimeMarshaled)
					// This should be set in storage but not modified in the original struct
					assert.NotEmpty(testTokenEntry.WrappingKeyId)
					assert.Empty(s.WrappingKeyId)
				} else {
					assert.EqualValues(s.CreationTimeMarshaled, testTokenEntry.CreationTimeMarshaled)
				}
			}

			loadId := s.Id
			if tt.loadIdOverride != nil {
				loadId = string(tt.loadIdOverride)
			}
			var loadStorage nodeenrollment.Storage
			if !tt.loadStorageNil {
				loadStorage = storage
			}
			loaded, err := types.LoadServerLedActivationToken(ctx, loadStorage, loadId, nodeenrollment.WithWrapper(tt.loadWrapper))
			switch tt.loadWantErrContains {
			case "":
				require.NoError(err)
			default:
				require.Error(err)
				assert.Contains(err.Error(), tt.loadWantErrContains)
				return
			}

			assert.Empty(cmp.Diff(s, loaded, protocmp.Transform()))
		})
	}
}
