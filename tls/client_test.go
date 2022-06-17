package tls

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestClientConfig(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fileStorage, err := file.New(ctx)
	require.NoError(t, err)
	t.Cleanup(fileStorage.Cleanup)

	_, err = rotation.RotateRootCertificates(ctx, fileStorage)
	require.NoError(t, err)

	// Create node credentials and have them authorized
	nodeCreds, err := registration.RegisterViaServerLedFlow(ctx, fileStorage, &types.ServerLedRegistrationRequest{})
	require.NoError(t, err)

	tests := []struct {
		name string
		// Return a modified node information and potentially a desired error string
		setupFn func(*types.NodeCredentials) (*types.NodeCredentials, string)
	}{
		{
			name: "invalid-nil",
			setupFn: func(in *types.NodeCredentials) (*types.NodeCredentials, string) {
				return nil, "nil input"
			},
		},
		{
			name: "invalid-nil-private-key",
			setupFn: func(in *types.NodeCredentials) (*types.NodeCredentials, string) {
				in.CertificatePrivateKeyPkcs8 = nil
				return in, "no certificate private key"
			},
		},
		{
			name: "invalid-unsupported-private-key",
			setupFn: func(in *types.NodeCredentials) (*types.NodeCredentials, string) {
				in.CertificatePrivateKeyType = types.KEYTYPE_X25519
				return in, "unsupported certificate private key"
			},
		},
		{
			name: "invalid-bad-cert-bundle-length",
			setupFn: func(in *types.NodeCredentials) (*types.NodeCredentials, string) {
				in.CertificateBundles = in.CertificateBundles[1:]
				return in, "invalid certificate bundles"
			},
		},
		{
			name: "valid",
			setupFn: func(in *types.NodeCredentials) (*types.NodeCredentials, string) {
				return in, ""
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			n := nodeCreds
			var wantErrContains string
			if tt.setupFn != nil {
				n, wantErrContains = tt.setupFn(proto.Clone(n).(*types.NodeCredentials))
			}

			resp, err := ClientConfig(ctx, n, nodeenrollment.WithServerName("foobar"))
			switch wantErrContains {
			case "":
				require.NoError(err)
				require.NotNil(resp)
			default:
				require.Error(err)
				assert.Contains(err.Error(), wantErrContains)
				return
			}

			// Check out the TLS parameters. Note that this doesn't re-check
			// parameters already tested via the tests on standardTlsConfig.
			// It's just checking the generated certificates.
			//
			// Also pools annoyingly have no way to pull certificates out of
			// them or iterate over them so we have to just try manually
			// validating certs, boo. We simply validate that the generated cert
			// validates against the returned roots.
			assert.Equal("foobar", resp.ServerName)
			assert.Len(resp.Certificates, 2)
			for _, tlsCert := range resp.Certificates {
				assert.Len(tlsCert.Certificate, 2)
				assert.Equal(tlsCert.Certificate[0], tlsCert.Leaf.Raw)
				assert.NotEmpty(tlsCert.PrivateKey)
				assert.NotEmpty(tlsCert.Certificate[1])

				verifyOpts := x509.VerifyOptions{
					Roots:     resp.RootCAs,
					KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				}

				if tlsCert.Leaf.NotBefore.Before(time.Now()) && tlsCert.Leaf.NotAfter.After(time.Now()) {
					chains, err := tlsCert.Leaf.Verify(verifyOpts)
					require.NoError(err)
					assert.Less(0, len(chains))
				}
			}

			// Break up NextProtos and check the request
			reqStr, err := CombineFromNextProtos(nodeenrollment.AuthenticateNodeNextProtoV1Prefix, resp.NextProtos)
			require.NoError(err)
			reqBytes, err := base64.RawStdEncoding.DecodeString(reqStr)
			require.NoError(err)
			var req types.GenerateServerCertificatesRequest
			require.NoError(proto.Unmarshal(reqBytes, &req))

			assert.Equal(nodeCreds.CertificatePublicKeyPkix, req.CertificatePublicKeyPkix)
			require.NotEmpty(req.Nonce)
			require.NotEmpty(req.NonceSignature)

			pubKey, err := x509.ParsePKIXPublicKey(req.CertificatePublicKeyPkix)
			require.NoError(err)
			require.True(ed25519.Verify(pubKey.(ed25519.PublicKey), req.Nonce, req.NonceSignature))
		})
	}
}
