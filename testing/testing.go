// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testing

import (
	"context"
	"testing"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	teststore "github.com/hashicorp/nodeenrollment/storage/testing"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/require"
)

// CommonTestParams is a one-stop shop returning a context, valid storage with
// root certificates, and pre-registered node credentials for testing
func CommonTestParams(t *testing.T, opt ...nodeenrollment.Option) (context.Context, nodeenrollment.NodeIdLoader, *types.NodeCredentials) {
	t.Helper()
	ctx := context.Background()

	storage, err := teststore.New(ctx)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(ctx, storage, opt...)
	require.NoError(t, err)

	_, activationToken, err := registration.CreateServerLedActivationToken(ctx, storage, &types.ServerLedRegistrationRequest{})
	require.NoError(t, err)
	nodeCreds, err := types.NewNodeCredentials(ctx, storage, nodeenrollment.WithActivationToken(activationToken))
	require.NoError(t, err)
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)
	fetchResp, err := registration.FetchNodeCredentials(ctx, storage, fetchReq)
	require.NoError(t, err)
	node, err := nodeCreds.HandleFetchNodeCredentialsResponse(ctx, storage, fetchResp)
	require.NoError(t, err)

	return ctx, storage, node
}
