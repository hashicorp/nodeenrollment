package file

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("nil", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := getOpts(nil)
		assert.NoError(err)
		assert.NotNil(opts)
	})
	t.Run("with-base-directory", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := getOpts()
		require.NoError(err)
		assert.Equal("", opts.withBaseDirectory)
		opts, err = getOpts(WithBaseDirectory("foobar"))
		require.NoError(err)
		assert.Equal("foobar", opts.withBaseDirectory)
	})
	t.Run("with-skip-cleanup", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := getOpts()
		require.NoError(err)
		assert.Equal(false, opts.withSkipCleanup)
		opts, err = getOpts(WithSkipCleanup(true))
		require.NoError(err)
		assert.True(opts.withSkipCleanup)
	})
}
