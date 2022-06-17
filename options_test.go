package nodeenrollment

import (
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("nil", func(t *testing.T) {
		assert := assert.New(t)
		opts, err := GetOpts(nil)
		assert.NoError(err)
		assert.NotNil(opts)
	})
	t.Run("with-certificate-lifetime", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts()
		require.NoError(err)
		assert.Equal(DefaultCertificateLifetime, opts.WithCertificateLifetime)
		opts, err = GetOpts(WithCertificateLifetime(time.Hour))
		require.NoError(err)
		assert.Equal(time.Hour, opts.WithCertificateLifetime)
	})
	t.Run("with-not-before-clock-skew", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts()
		require.NoError(err)
		assert.Equal(DefaultNotBeforeClockSkewDuration, opts.WithNotBeforeClockSkew)
		opts, err = GetOpts(WithNotBeforeClockSkew(time.Hour))
		require.NoError(err)
		assert.Equal(time.Hour, opts.WithNotBeforeClockSkew)
	})
	t.Run("with-not-after-clock-skew", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts()
		require.NoError(err)
		assert.Equal(DefaultNotAfterClockSkewDuration, opts.WithNotAfterClockSkew)
		opts, err = GetOpts(WithNotAfterClockSkew(time.Hour))
		require.NoError(err)
		assert.Equal(time.Hour, opts.WithNotAfterClockSkew)
	})
	t.Run("with-random-reader", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts()
		require.NoError(err)
		assert.Equal(rand.Reader, opts.WithRandomReader)
		opts, err = GetOpts(WithRandomReader(nil))
		require.NoError(err)
		assert.Nil(opts.WithRandomReader)
	})
	t.Run("with-nonce", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts()
		require.NoError(err)
		assert.Empty(opts.WithNonce)
		opts, err = GetOpts(WithNonce("foobar"))
		require.NoError(err)
		assert.Equal("foobar", opts.WithNonce)
	})
	t.Run("with-tls-verify-func", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts()
		require.NoError(err)
		assert.Nil(opts.WithTlsVerifyOptionsFunc)
		verifyFunc := func(*x509.CertPool) x509.VerifyOptions { return x509.VerifyOptions{} }
		opts, err = GetOpts(WithTlsVerifyOptionsFunc(verifyFunc))
		require.NoError(err)
		assert.NotNil(opts.WithTlsVerifyOptionsFunc)
	})
	t.Run("with-wrapper", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts()
		require.NoError(err)
		assert.Nil(opts.WithWrapper)
		wrapper := new(wrapping.TestWrapper)
		opts, err = GetOpts(WithWrapper(wrapper))
		require.NoError(err)
		assert.Equal(wrapper, opts.WithWrapper)
	})
	t.Run("with-skip-storage", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts()
		require.NoError(err)
		assert.False(opts.WithSkipStorage)
		opts, err = GetOpts(WithSkipStorage(true))
		require.NoError(err)
		assert.True(opts.WithSkipStorage)
	})
	t.Run("with-expected-public-key", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts()
		require.NoError(err)
		assert.Empty(opts.WithExpectedPublicKey)
		opts, err = GetOpts(WithExpectedPublicKey([]byte("foobar")))
		require.NoError(err)
		assert.Equal([]byte("foobar"), opts.WithExpectedPublicKey)
	})
	t.Run("with-state", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts()
		require.NoError(err)
		assert.Empty(opts.WithState)
		structMap := map[string]interface{}{"foo": "bar"}
		state, err := structpb.NewStruct(structMap)
		require.NoError(err)
		opts, err = GetOpts(WithState(state))
		require.NoError(err)
		assert.Equal(structMap, opts.WithState.AsMap())
	})
	t.Run("with-alpn-proto-prefix", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts()
		require.NoError(err)
		assert.Empty(opts.WithAlpnProtoPrefix)
		opts, err = GetOpts(WithAlpnProtoPrefix(FetchNodeCredsNextProtoV1Prefix))
		require.NoError(err)
		assert.Equal(FetchNodeCredsNextProtoV1Prefix, opts.WithAlpnProtoPrefix)
		opts, err = GetOpts(WithAlpnProtoPrefix(AuthenticateNodeNextProtoV1Prefix))
		require.NoError(err)
		assert.Equal(AuthenticateNodeNextProtoV1Prefix, opts.WithAlpnProtoPrefix)
		opts, err = GetOpts(WithAlpnProtoPrefix("foobar"))
		require.Error(err)
	})
	t.Run("with-server-name", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		opts, err := GetOpts()
		require.NoError(err)
		assert.Empty(opts.WithServerName)
		opts, err = GetOpts(WithServerName("foobar"))
		require.NoError(err)
		assert.Equal("foobar", opts.WithServerName)
	})
}
