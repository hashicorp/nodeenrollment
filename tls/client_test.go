// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package tls

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/hashicorp/nodeenrollment"
	nodetesting "github.com/hashicorp/nodeenrollment/testing"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestClientConfigs(t *testing.T) {
	t.Parallel()

	ctx, _, nodeCreds := nodetesting.CommonTestParams(t)

	withState, err := structpb.NewStruct(map[string]any{
		"foo": "bar",
	})
	require.NoError(t, err)

	tests := []struct {
		name string
		// Return a modified node information and potentially a desired error string
		setupFn func(*types.NodeCredentials) (*types.NodeCredentials, string)
		state   *structpb.Struct
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
		{
			name: "valid-with-state",
			setupFn: func(in *types.NodeCredentials) (*types.NodeCredentials, string) {
				return in, ""
			},
			state: withState,
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

			tlsConfigs, err := ClientConfigs(ctx, n, nodeenrollment.WithServerName("foobar"), nodeenrollment.WithExtraAlpnProtos([]string{"foo", "bar"}), nodeenrollment.WithState(tt.state))
			switch wantErrContains {
			case "":
				require.NoError(err)
				// We'll only have one because the second won't be valid yet
				require.Len(tlsConfigs, 1)
			default:
				require.Error(err)
				assert.Contains(err.Error(), wantErrContains)
				return
			}

			// Pull out the key identifier
			tlsConfig := tlsConfigs[0]

			// Check out the TLS parameters. Note that this doesn't re-check
			// parameters already tested via the tests on standardTlsConfig.
			// It's just checking the generated certificates.
			//
			// Also pools annoyingly have no way to pull certificates out of
			// them or iterate over them so we have to just try manually
			// validating certs, boo. We simply validate that the generated cert
			// validates against the returned roots.
			assert.Equal("foobar", tlsConfig.ServerName)
			assert.Contains(tlsConfig.NextProtos, "foo")
			assert.Contains(tlsConfig.NextProtos, "bar")

			expCaCert, err := x509.ParseCertificate(n.CertificateBundles[0].CaCertificateDer)
			require.NoError(err)
			tlsCert, err := tlsConfig.GetClientCertificate(&tls.CertificateRequestInfo{
				AcceptableCAs: [][]byte{expCaCert.RawSubject},
			})
			require.NoError(err)
			require.NotNil(tlsCert)
			assert.NotEmpty(tlsCert.PrivateKey)
			assert.NotEmpty(tlsCert.Certificate[1])

			verifyOpts := x509.VerifyOptions{
				Roots:     tlsConfig.RootCAs,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}

			if tlsCert.Leaf.NotBefore.Before(time.Now()) && tlsCert.Leaf.NotAfter.After(time.Now()) {
				chains, err := tlsCert.Leaf.Verify(verifyOpts)
				require.NoError(err)
				assert.Less(0, len(chains))
			}

			// Break up NextProtos and check the request
			reqStr, err := CombineFromNextProtos(nodeenrollment.AuthenticateNodeNextProtoV1Prefix, tlsConfig.NextProtos)
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

			if tt.state != nil {
				require.NotEmpty(req.ClientState)
				require.NotEmpty(req.ClientStateSignature)
				require.True(ed25519.Verify(pubKey.(ed25519.PublicKey), req.ClientState, req.ClientStateSignature))
			}
		})
	}
}
