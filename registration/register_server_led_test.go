// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package registration_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/inmem"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestServerLedRegistration(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(err)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(err)

	// Ensure nil request and/or storage are caught
	_, token, err := registration.CreateServerLedActivationToken(ctx, nil, &types.ServerLedRegistrationRequest{})
	require.Error(err)
	assert.Contains(err.Error(), "nil storage")
	assert.Empty(token)
	_, token, err = registration.CreateServerLedActivationToken(ctx, storage, nil)
	require.Error(err)
	assert.Contains(err.Error(), "nil request")
	assert.Empty(token)

	wrapper := aead.TestWrapper(t)

	tokenId, token, err := registration.CreateServerLedActivationToken(ctx, storage, &types.ServerLedRegistrationRequest{}, nodeenrollment.WithWrapper(wrapper))
	require.NoError(err)
	assert.NotEmpty(token)
	assert.True(strings.HasPrefix(token, nodeenrollment.ServerLedActivationTokenPrefix))

	nonce, err := base58.FastBase58Decoding(strings.TrimPrefix(token, nodeenrollment.ServerLedActivationTokenPrefix))
	require.NoError(err)

	// We should now look for a ServerLedActivationToken value in storage and validate it
	tokenNonce := new(types.ServerLedActivationTokenNonce)
	require.NoError(proto.Unmarshal(nonce, tokenNonce))
	hm := hmac.New(sha256.New, tokenNonce.HmacKeyBytes)
	idBytes := hm.Sum(tokenNonce.Nonce)
	assert.Equal(tokenId, base58.FastBase58Encoding(idBytes))
	tokenEntry, err := types.LoadServerLedActivationToken(ctx, storage, base58.FastBase58Encoding(idBytes), nodeenrollment.WithWrapper(wrapper))
	require.NoError(err)
	require.NotNil(tokenEntry)
	assert.NotEmpty(tokenEntry.Id)
	assert.NotNil(tokenEntry.CreationTime)
	assert.NotEmpty(tokenEntry.CreationTimeMarshaled)
	assert.Empty(tokenEntry.WrappingKeyId)
}
