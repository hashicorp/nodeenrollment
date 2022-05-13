package types_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRoot_Generation(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()

	storage, err := file.NewFileStorage(ctx)
	require.NoError(err)
	t.Cleanup(storage.Cleanup)

	roots, err := rotation.RotateRootCertificates(ctx, storage)

	for _, root := range []*types.RootCertificate{roots.Current, roots.Next} {
		require.NoError(err)
		assert.NotEmpty(root.Id)
		assert.NotEmpty(root.PublicKeyPkix)
		assert.NotEmpty(root.CertificateDer)
		assert.NotEmpty(root.NotAfter)
		assert.NotEmpty(root.NotBefore)
		assert.NotEmpty(root.PrivateKeyPkcs8)
		assert.Equal(types.KEYTYPE_KEYTYPE_ED25519, root.PrivateKeyType)
		assert.Empty(root.WrappingKeyId)

		startingCert := proto.Clone(root).(*types.RootCertificate)

		// Store via the root method without a wrapper
		require.NoError(root.Store(ctx, storage))

		// Validate what we read back both from storage and from the function
		// matches
		lowLevelVal := &types.RootCertificate{Id: root.Id}
		require.NoError(storage.Load(ctx, lowLevelVal))
		require.NoError(err)
		assert.Empty(lowLevelVal.WrappingKeyId)
		assert.Empty(cmp.Diff(startingCert, lowLevelVal, protocmp.Transform()))
		highLevelVal, err := types.LoadRootCertificate(ctx, storage, root.Id)
		require.NoError(err)
		assert.Empty(highLevelVal.WrappingKeyId)
		assert.Empty(cmp.Diff(startingCert, highLevelVal, protocmp.Transform()))

		// Now re-store passing a wrapper and verify that it's _not_ the same in
		// storage, but is when it's read back
		realWrapper := wrapping.TestWrapper(t)
		fakeWrapper := wrapping.TestWrapper(t)

		// Store again, using a wrapper
		require.NoError(root.Store(ctx, storage, nodeenrollment.WithWrapper(realWrapper)))

		// Run tests
		lowLevelVal = &types.RootCertificate{Id: root.Id}
		require.NoError(storage.Load(ctx, lowLevelVal))
		assert.NotEmpty(lowLevelVal.WrappingKeyId)
		assert.NotEqual(startingCert.PrivateKeyPkcs8, lowLevelVal.PrivateKeyPkcs8)
		assert.NotEmpty(cmp.Diff(startingCert, lowLevelVal, protocmp.Transform()))
		_, err = types.LoadRootCertificate(ctx, storage, root.Id, nodeenrollment.WithWrapper(fakeWrapper))
		require.Error(err) // should fail due to wrong wrapper
		highLevelVal, err = types.LoadRootCertificate(ctx, storage, root.Id, nodeenrollment.WithWrapper(realWrapper))
		require.NoError(err)
		assert.Empty(highLevelVal.WrappingKeyId)
		assert.Empty(cmp.Diff(startingCert, highLevelVal, protocmp.Transform()))
	}
}
