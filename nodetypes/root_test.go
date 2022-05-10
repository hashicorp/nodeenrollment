package nodetypes_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/nodestorage/file"
	"github.com/hashicorp/nodeenrollment/nodetesting"
	"github.com/hashicorp/nodeenrollment/nodetypes"
	"github.com/hashicorp/nodeenrollment/rotation"
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

	for _, root := range []*nodetypes.RootCertificate{roots.Current, roots.Next} {
		require.NoError(err)
		assert.NotEmpty(root.Id)
		assert.NotEmpty(root.PublicKeyPkix)
		assert.NotEmpty(root.CertificateDer)
		assert.NotEmpty(root.NotAfter)
		assert.NotEmpty(root.NotBefore)
		assert.NotEmpty(root.PrivateKeyPkcs8)
		assert.Equal(nodetypes.KEYTYPE_KEYTYPE_ED25519, root.PrivateKeyType)
		assert.Empty(root.WrappingKeyId)

		startingCert := proto.Clone(root).(*nodetypes.RootCertificate)

		// Store via the root method without a wrapper
		require.NoError(root.Store(ctx, storage))

		// Validate what we read back both from storage and from the function
		// matches
		lowLevelVal := &nodetypes.RootCertificate{Id: root.Id}
		require.NoError(storage.Load(ctx, lowLevelVal))
		require.NoError(err)
		assert.Empty(lowLevelVal.WrappingKeyId)
		assert.Empty(cmp.Diff(startingCert, lowLevelVal, protocmp.Transform()))
		highLevelVal, err := nodetypes.LoadRootCertificate(ctx, storage, root.Id)
		require.NoError(err)
		assert.Empty(highLevelVal.WrappingKeyId)
		assert.Empty(cmp.Diff(startingCert, highLevelVal, protocmp.Transform()))

		// Now re-store passing a wrapper and verify that it's _not_ the same in
		// storage, but is when it's read back
		realWrapper := nodetesting.TestWrapper(t)
		fakeWrapper := nodetesting.TestWrapper(t)

		// Store again, using a wrapper
		require.NoError(root.Store(ctx, storage, nodee.WithWrapper(realWrapper)))

		// Run tests
		lowLevelVal = &nodetypes.RootCertificate{Id: root.Id}
		require.NoError(storage.Load(ctx, lowLevelVal))
		assert.NotEmpty(lowLevelVal.WrappingKeyId)
		assert.NotEqual(startingCert.PrivateKeyPkcs8, lowLevelVal.PrivateKeyPkcs8)
		assert.NotEmpty(cmp.Diff(startingCert, lowLevelVal, protocmp.Transform()))
		_, err = nodetypes.LoadRootCertificate(ctx, storage, root.Id, nodee.WithWrapper(fakeWrapper))
		require.Error(err) // should fail due to wrong wrapper
		highLevelVal, err = nodetypes.LoadRootCertificate(ctx, storage, root.Id, nodee.WithWrapper(realWrapper))
		require.NoError(err)
		assert.Empty(highLevelVal.WrappingKeyId)
		assert.Empty(cmp.Diff(startingCert, highLevelVal, protocmp.Transform()))
	}
}
