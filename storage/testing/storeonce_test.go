// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testing

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_StorageLifecycle(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()

	ts, err := New(ctx)
	require.NoError(err)
	numNodeInfos := 5

	nodeId := "nodeIdForTest"
	for i := 0; i < numNodeInfos; i++ {
		name := fmt.Sprintf("node-info-%d", i)
		newNode := &types.NodeInformation{
			Id:     name,
			NodeId: nodeId,
		}
		err = ts.Store(ctx, newNode)
		require.NoError(err)
	}

	// Store a few unrelated NodeInfos
	for i := 0; i < numNodeInfos; i++ {
		name := fmt.Sprintf("other-node-info-%d", i)
		newNode := &types.NodeInformation{
			Id:     name,
			NodeId: "these-are-not-the-nodes-you-are-looking-for",
		}
		err = ts.Store(ctx, newNode)
		require.NoError(err)
	}

	searchInfo := &types.NodeInformations{
		NodeId: nodeId,
	}

	err = ts.LoadByNodeId(ctx, searchInfo)
	require.NoError(err)
	assert.Equal(numNodeInfos, len(searchInfo.Nodes))
	for _, s := range searchInfo.Nodes {
		assert.Equal(nodeId, s.NodeId)
	}
}
