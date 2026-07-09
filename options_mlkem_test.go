// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

// This file is in package nodeenrollment_test (external test package) to avoid
// an import cycle: the types sub-package imports nodeenrollment, so the
// internal test package cannot import types.
package nodeenrollment_test

import (
	"testing"

	nodeenrollment "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOpts_WithMlkemParameters(t *testing.T) {
	t.Parallel()
	t.Run("with-mlkem-parameters", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := nodeenrollment.GetOpts()
		require.NoError(err)
		assert.Nil(opts.WithMlkemParameters)
		_, err = nodeenrollment.GetOpts(nodeenrollment.WithMlkemParameters(nil))
		require.Error(err)
		_, err = nodeenrollment.GetOpts(nodeenrollment.WithMlkemParameters(&types.NodeCredentials{}))
		require.Error(err)
		params := &types.MLKEMParameters{EncapsulationKey: []byte("foobar")}
		opts, err = nodeenrollment.GetOpts(nodeenrollment.WithMlkemParameters(params))
		require.NoError(err)
		assert.Equal(params, opts.WithMlkemParameters)
	})
}
