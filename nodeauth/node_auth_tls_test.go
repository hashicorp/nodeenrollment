package nodeauth

import (
	"crypto/tls"
	"testing"

	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/stretchr/testify/assert"
)

func TestContainsNodeAuthAlpnProto(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		in    *tls.ClientHelloInfo
		found bool
	}{
		{
			name: "fetch-found",
			in: &tls.ClientHelloInfo{
				SupportedProtos: []string{"foobar", nodee.FetchNodeCredsNextProtoV1Prefix + "boofar"},
			},
			found: true,
		},
		{
			name: "auth-found",
			in: &tls.ClientHelloInfo{
				SupportedProtos: []string{"foobar", nodee.AuthenticateNodeNextProtoV1Prefix + "foobar"},
			},
			found: true,
		},
		{
			name: "not-found",
			in: &tls.ClientHelloInfo{
				SupportedProtos: []string{"foobar"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.found, ContainsNodeAuthAlpnProto(tt.in.SupportedProtos...))
		})
	}
}

/*
func TestNodeAuthTlsConfig(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	fileStorage, err := file.NewFileStorage(ctx)
	require.NoError(t, err)
	t.Cleanup(fileStorage.Cleanup)
	storage := nodee.NopTransactionStorage(fileStorage)

	_, err = nodetypes.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	defaultFactory := MakeCurrentParametersFactory(ctx, storage)

	tests := []struct {
		name                      string
		factoryFn                 CurrentParameterFactory
		hello                     *tls.ClientHelloInfo
		shouldBeValidFetch        bool
		shouldBeValidAuth         bool
		wantValidationErrContains string
		wantConfigErrContains     string
	}{
		{
			name:                      "nil storage",
			factoryFn:                 MakeCurrentParametersFactory(ctx, nil),
			wantValidationErrContains: "nil storage input",
		},
		{
			name:                      "no supported protos",
			factoryFn:                 defaultFactory,
			hello:                     &tls.ClientHelloInfo{},
			wantValidationErrContains: "no valid alpn supported protos value found",
		},
		{
			name:      "valid conf from fetch proto",
			factoryFn: defaultFactory,
			hello: &tls.ClientHelloInfo{
				SupportedProtos: []string{nodee.FetchNodeCredsNextProtoV1Prefix},
			},
			shouldBeValidFetch: true,
		},
		{
			name:      "valid conf from auth proto",
			factoryFn: defaultFactory,
			hello: &tls.ClientHelloInfo{
				SupportedProtos: []string{nodee.AuthenticateNodeNextProtoV1Prefix},
			},
			shouldBeValidAuth: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			if tt.wantValidationErrContains != "" {
				ctx, storage, opt := tt.factoryFn()
				_, err := NodeTlsConfig(ctx, storage, nil, opt...)(tt.hello)
				require.Error(err)
				assert.Contains(err.Error(), tt.wantValidationErrContains)
				return
			}
			ctx, storage, opt := tt.factoryFn()
			tlsConf, err := NodeTlsConfig(ctx, storage, nil, opt...)(tt.hello)
			if tt.wantConfigErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantConfigErrContains)
				return
			}
			require.NoError(err)
			switch {
			case tt.shouldBeValidFetch:
				assert.Equal(tls.RequireAnyClientCert, tlsConf.ClientAuth)
				assert.Equal(true, tlsConf.InsecureSkipVerify)
				assert.Nil(tlsConf.VerifyConnection)
				require.Len(tlsConf.NextProtos, 1)
				assert.Equal(nodee.FetchNodeCredsNextProtoV1Prefix, tlsConf.NextProtos[0])
				return
			case tt.shouldBeValidAuth:
				assert.Equal(tls.RequireAnyClientCert, tlsConf.ClientAuth)
				assert.Equal(true, tlsConf.InsecureSkipVerify)
				assert.NotNil(tlsConf.VerifyConnection)
				require.Len(tlsConf.NextProtos, 1)
				assert.Contains(tlsConf.NextProtos[0], nodee.AuthenticateNodeNextProtoV1Prefix)
				return
			}
		})
	}
}
*/
