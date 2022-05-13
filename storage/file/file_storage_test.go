package file

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// This test creates some on-disk entries, validates that they are found/listed,
// and attempts and validates removing one. Then ensures that the current one is
// the most recent.
func Test_TestStorage_RootCertificates(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	const numRoots = 3

	ts, err := NewFileStorage(ctx)
	require.NoError(err)
	t.Cleanup(ts.Cleanup)
	t.Log("base dir for test", ts.BaseDir())

	roots := make(map[string]*types.RootCertificate)
	var name string
	for i := 0; i < numRoots; i++ {
		name = fmt.Sprintf("%d", i)
		newRoot := &types.RootCertificate{
			PrivateKeyPkcs8: []byte(name),
			NotAfter:        timestamppb.New(time.Now().Add(-1 * time.Hour * time.Duration(i))),
		}
		require.Error(ts.Store(ctx, newRoot)) // Should fail because no id set
		newRoot.Id = name
		require.NoError(ts.Store(ctx, newRoot))
		roots[name] = newRoot
	}

	rootIds, err := ts.List(ctx, (*types.RootCertificate)(nil))
	require.NoError(err)
	assert.Len(rootIds, numRoots)
	for _, rootId := range rootIds {
		root := &types.RootCertificate{Id: rootId}
		require.NoError(ts.Load(ctx, root))
		require.NoError(err)
		assert.Equal(string(root.PrivateKeyPkcs8), rootId)
	}

	midname := string(roots[fmt.Sprintf("%d", numRoots/2)].PrivateKeyPkcs8)
	require.NoError(ts.Remove(ctx, &types.RootCertificate{Id: midname}))
	delete(roots, midname)

	rootIds, err = ts.List(ctx, (*types.RootCertificate)(nil))
	require.NoError(err)
	assert.Len(rootIds, numRoots-1)
	for _, rootId := range rootIds {
		root := &types.RootCertificate{Id: rootId}
		require.NoError(ts.Load(ctx, root))
		assert.Equal(string(root.PrivateKeyPkcs8), rootId)
	}
}
