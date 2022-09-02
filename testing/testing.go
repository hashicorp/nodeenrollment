package testing

import (
	"context"
	"testing"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/require"
)

// CommonTestParams is a one-stop shop returning a context, valid storage with
// root certificates, and pre-registered node credentials for testing
func CommonTestParams(t *testing.T) (context.Context, nodeenrollment.Storage, *types.NodeCredentials) {
	t.Helper()
	ctx := context.Background()

	storage, err := file.New(ctx)
	require.NoError(t, err)
	t.Cleanup(storage.Cleanup)

	_, err = rotation.RotateRootCertificates(ctx, storage)
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
