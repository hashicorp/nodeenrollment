package file

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This test creates some on-disk entries, validates that they are found/listed
// and can be read, and attempts and validates removing one.
func Test_StorageLifecycle(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()
	const numRoots = 3

	ts, err := New(ctx)
	require.NoError(err)
	t.Cleanup(ts.Cleanup)

	// Create three roots and store them. After we store each, expect that the
	// number of found items in a list is equivalent.
	roots := make(map[string]*types.RootCertificates)
	var name string
	for i := 0; i < numRoots; i++ {
		name = fmt.Sprintf("%d", i)
		newRoots := &types.RootCertificates{
			Current: &types.RootCertificate{
				PrivateKeyPkcs8: []byte(name),
			},
		}
		require.Error(ts.Store(ctx, newRoots)) // Should fail because no id set
		newRoots.Id = name
		require.NoError(ts.Store(ctx, newRoots)) // Id is now set so should work
		roots[name] = newRoots
		rootIds, err := ts.List(ctx, (*types.RootCertificates)(nil))
		require.NoError(err)
		require.Len(rootIds, i+1) // this also ensrues since the names are changing that there isn't a duplication/overwriting scenario
	}

	// Now ensure that the listed items actually match! We know the length is
	// correct, so if any aren't found then it's an issue. Load each and ensure
	// the ID matches.
	rootIds, err := ts.List(ctx, (*types.RootCertificates)(nil))
	require.NoError(err)
	assert.Len(rootIds, numRoots)
	for _, rootId := range rootIds {
		_, found := roots[rootId]
		require.True(found) // matches something we created above

		roots := &types.RootCertificates{Id: rootId}
		require.NoError(ts.Load(ctx, roots))
		require.NoError(err)
		assert.Equal(string(roots.Current.PrivateKeyPkcs8), rootId)
	}

	// Remove one of the roots
	midname := string(roots[fmt.Sprintf("%d", numRoots/2)].Current.PrivateKeyPkcs8)
	require.NoError(ts.Remove(ctx, &types.RootCertificates{Id: midname}))
	delete(roots, midname)

	// Ensure we no longer see it
	rootIds, err = ts.List(ctx, (*types.RootCertificates)(nil))
	require.NoError(err)
	assert.Len(rootIds, numRoots-1)
	for _, rootId := range rootIds {
		roots := &types.RootCertificates{Id: rootId}
		require.NoError(ts.Load(ctx, roots))
		assert.Equal(string(roots.Current.PrivateKeyPkcs8), rootId)
	}
}

// This simple test ensures that we succeed on all types we know how to store
// and fail on a type we don't know how to store
func Test_StorageMessageType(t *testing.T) {
	t.Parallel()
	tRequire := require.New(t)
	ctx := context.Background()

	ts, err := New(ctx)
	tRequire.NoError(err)
	t.Cleanup(ts.Cleanup)

	tests := []struct {
		name            string
		msg             nodeenrollment.MessageWithId
		wantErrContains string
	}{
		{
			name: "valid-node-credentials",
			msg:  &types.NodeCredentials{Id: "foobar"},
		},
		{
			name: "valid-node-information",
			msg:  &types.NodeInformation{Id: "foobar"},
		},
		{
			name: "valid-root-certificates",
			msg:  &types.RootCertificates{Id: "foobar"},
		},
		{
			name: "valid-server-led-activation-token",
			msg:  &types.ServerLedActivationToken{Id: "foobar"},
		},
		{
			name:            "nil-msg",
			wantErrContains: "nil message",
		},
		{
			name:            "no-id",
			msg:             &types.RootCertificates{},
			wantErrContains: "no id given",
		},
		{
			name:            "unknown-msg",
			msg:             new(types.FetchNodeCredentialsInfo),
			wantErrContains: "unknown message type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subtAssert, subtRequire := assert.New(t), require.New(t)
			err := ts.Store(ctx, tt.msg)
			switch tt.wantErrContains {
			case "":
				subtAssert.NoError(err)
			default:
				subtRequire.Error(err)
				subtAssert.Contains(err.Error(), tt.wantErrContains)
			}
		})
	}
}
