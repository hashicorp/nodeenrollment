// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package types_test

import (
	"testing"

	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDuplicateRecordError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		nodeInfo          *types.NodeInformation
		wantError         bool
		wantErrorContains string
	}{
		{
			name:              "missing-node-info",
			wantError:         true,
			wantErrorContains: "(nodeenrollment.types.NewDuplicateRecordError) nil node information",
		},
		{
			name:     "success",
			nodeInfo: &types.NodeInformation{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			dre, err := types.NewDuplicateRecordError(tt.nodeInfo)
			if tt.wantError {
				assert.ErrorContains(err, tt.wantErrorContains)
				return
			}
			require.NotNil(dre)
			require.Equal(tt.nodeInfo, dre.GetNodeInformation())
		})
	}
}
