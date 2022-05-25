package rotation

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRotateRootCertificates(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()

	storage, err := file.NewFileStorage(ctx)
	require.NoError(err)
	t.Cleanup(storage.Cleanup)

	// Ensure nil storage fails
	roots, err := RotateRootCertificates(ctx, nil)
	require.Error(err)
	assert.Nil(roots)

	// First validate the generated parameters
	var current, next *types.RootCertificate
	roots, err = RotateRootCertificates(ctx, storage)
	for _, root := range []*types.RootCertificate{roots.Current, roots.Next} {
		require.NoError(err)
		assert.NotEmpty(root.Id)
		assert.NotEmpty(root.PublicKeyPkix)
		assert.NotEmpty(root.CertificateDer)
		assert.NotEmpty(root.NotAfter)
		assert.NotEmpty(root.NotBefore)
		assert.NotEmpty(root.PrivateKeyPkcs8)
		assert.Equal(types.KEYTYPE_ED25519, root.PrivateKeyType)
		assert.Empty(root.WrappingKeyId)
		if nodeenrollment.KnownId(root.Id) == nodeenrollment.CurrentId {
			current = root
		} else {
			next = root
		}
	}

	// If we call again immediately nothing should happen, should be same roots
	r2, err := RotateRootCertificates(ctx, storage)
	require.NoError(err)
	assert.Empty(cmp.Diff(r2.Current, current, protocmp.Transform()))
	assert.Empty(cmp.Diff(r2.Next, next, protocmp.Transform()))

	require.NotEmpty(current)
	require.NotEmpty(next)

	// Now validate the timeframes
	now := time.Now()
	assert.Less(current.NotBefore.AsTime().Sub(now)+5*time.Minute, time.Minute)
	assert.Less(current.NotAfter.AsTime().Sub(now)-nodeenrollment.DefaultCertificateLifetime, time.Minute)
	shift := current.NotAfter.AsTime().Sub(now) / 2
	assert.Less(next.NotBefore.AsTime().Sub(now)+5*time.Minute-shift, time.Minute)
	assert.Less(next.NotAfter.AsTime().Sub(now)-nodeenrollment.DefaultCertificateLifetime-shift, time.Minute)
}

func TestDecideWhatToMake(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	storage, err := file.NewFileStorage(ctx)
	require.NoError(t, err)
	t.Cleanup(storage.Cleanup)

	// Get some to modify
	roots, err := RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	tests := []struct {
		name          string
		current, next *types.RootCertificate
		currentNotBeforeOverride,
		currentNotAfterOverride,
		nextNotBeforeOverride,
		nextNotAfterOverride time.Time
		expToMake      []nodeenrollment.KnownId
		expNextCurrent *types.RootCertificate
	}{
		{
			name:      "all-nil",
			expToMake: []nodeenrollment.KnownId{nodeenrollment.CurrentId, nodeenrollment.NextId},
		},
		{
			name:    "both-valid",
			current: roots.Current,
			next:    roots.Next,
		},
		{
			name:                  "both-valid-in-rotation-window",
			current:               roots.Current,
			next:                  roots.Next,
			nextNotBeforeOverride: time.Now().Add(-1 * time.Minute),
			expToMake:             []nodeenrollment.KnownId{nodeenrollment.NextId},
			expNextCurrent:        roots.Next,
		},
		{
			name:      "no-current",
			next:      roots.Next,
			expToMake: []nodeenrollment.KnownId{nodeenrollment.CurrentId, nodeenrollment.NextId},
		},
		{
			name:      "no-next",
			current:   roots.Current,
			expToMake: []nodeenrollment.KnownId{nodeenrollment.CurrentId, nodeenrollment.NextId},
		},
		{
			name:                    "current-expired-next-not-ready",
			current:                 roots.Current,
			next:                    roots.Next,
			currentNotAfterOverride: time.Now().Add(-1 * time.Minute),
			nextNotBeforeOverride:   time.Now().Add(time.Minute),
			expToMake:               []nodeenrollment.KnownId{nodeenrollment.CurrentId, nodeenrollment.NextId},
		},
		{
			name:                    "current-expired-next-ready",
			current:                 roots.Current,
			next:                    roots.Next,
			currentNotAfterOverride: time.Now().Add(-1 * time.Minute),
			nextNotBeforeOverride:   time.Now().Add(-1 * time.Minute),
			expToMake:               []nodeenrollment.KnownId{nodeenrollment.NextId},
			expNextCurrent:          roots.Next,
		},
		{
			name:                     "current-not-yet-valid-next-ready",
			current:                  roots.Current,
			next:                     roots.Next,
			currentNotBeforeOverride: time.Now().Add(1 * time.Minute),
			nextNotBeforeOverride:    time.Now().Add(-1 * time.Minute),
			expToMake:                []nodeenrollment.KnownId{nodeenrollment.CurrentId, nodeenrollment.NextId},
		},
		{
			name:                     "current-not-yet-valid-next-not-ready",
			current:                  roots.Current,
			next:                     roots.Next,
			currentNotBeforeOverride: time.Now().Add(1 * time.Minute),
			expToMake:                []nodeenrollment.KnownId{nodeenrollment.CurrentId, nodeenrollment.NextId},
		},
		{
			name:                 "current-valid-next-expired",
			current:              roots.Current,
			next:                 roots.Next,
			nextNotAfterOverride: time.Now().Add(-1 * time.Minute),
			expToMake:            []nodeenrollment.KnownId{nodeenrollment.NextId},
			expNextCurrent:       roots.Current,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			inCurrent := tt.current
			if inCurrent != nil {
				inCurrent = proto.Clone(inCurrent).(*types.RootCertificate)
				if !tt.currentNotBeforeOverride.IsZero() {
					inCurrent.NotBefore = timestamppb.New(tt.currentNotBeforeOverride)
				}
				if !tt.currentNotAfterOverride.IsZero() {
					inCurrent.NotAfter = timestamppb.New(tt.currentNotAfterOverride)
				}
			}
			inNext := tt.next
			if inNext != nil {
				inNext = proto.Clone(inNext).(*types.RootCertificate)
				if !tt.nextNotBeforeOverride.IsZero() {
					inNext.NotBefore = timestamppb.New(tt.nextNotBeforeOverride)
				}
				if !tt.nextNotAfterOverride.IsZero() {
					inNext.NotAfter = timestamppb.New(tt.nextNotAfterOverride)
				}
			}

			toMake, nextCurrent := decideWhatToMake(&types.RootCertificates{
				Current: inCurrent,
				Next:    inNext,
			})

			assert.Equal(tt.expToMake, toMake)

			if tt.expNextCurrent != nil {
				require.NotNil(nextCurrent)
				// We may have modified timestamps so ignore that here. Private
				// key will still be a differentiator.
				expNext := proto.Clone(tt.expNextCurrent).(*types.RootCertificate)
				expNext.NotBefore = nextCurrent.NotBefore
				expNext.NotAfter = nextCurrent.NotAfter
				assert.Empty(cmp.Diff(expNext, nextCurrent, protocmp.Transform()))
			}
		})
	}
}
