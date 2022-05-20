package tls

import (
	"context"
	"crypto"
	"crypto/rand"
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

func TestGenerateServerCertificates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fileStorage, err := file.NewFileStorage(ctx)
	require.NoError(t, err)
	t.Cleanup(fileStorage.Cleanup)

	_, err = rotation.RotateRootCertificates(ctx, fileStorage)
	require.NoError(t, err)

	// Create node credentials and have them authorized
	nodeCreds, err := registration.RegisterViaOperatorLedFlow(ctx, fileStorage, &types.OperatorLedRegistrationRequest{})
	require.NoError(t, err)

	nonceBytes := make([]byte, nodeenrollment.NonceSize)
	w, err := rand.Read(nonceBytes)
	require.NoError(t, err)
	require.EqualValues(t, w, nodeenrollment.NonceSize)

	privKey, err := x509.ParsePKCS8PrivateKey(nodeCreds.CertificatePrivateKeyPkcs8)
	require.NoError(t, err)
	nonceSigBytes, err := privKey.(crypto.Signer).Sign(rand.Reader, nonceBytes, crypto.Hash(0))
	require.NoError(t, err)

	genReq := &types.GenerateServerCertificatesRequest{
		CertificatePublicKeyPkix: nodeCreds.CertificatePublicKeyPkix,
		Nonce:                    nonceBytes,
		NonceSignature:           nonceSigBytes,
	}

	tests := []struct {
		name string
		// Return a modified node information and potentially a desired error string
		setupFn func(*types.GenerateServerCertificatesRequest) (*types.GenerateServerCertificatesRequest, string)
		// Flag to set storage to nil
		storageNil bool
	}{
		{
			name:       "invalid-no-storage",
			storageNil: true,
		},
		{
			name: "invalid-nil",
			setupFn: func(req *types.GenerateServerCertificatesRequest) (*types.GenerateServerCertificatesRequest, string) {
				return nil, "nil request"
			},
		},
		{
			name: "invalid-verification-no-nonce",
			setupFn: func(req *types.GenerateServerCertificatesRequest) (*types.GenerateServerCertificatesRequest, string) {
				req.Nonce = nil
				return req, "empty nonce"
			},
		},
		{
			name: "invalid-verification-no-nonce-signature",
			setupFn: func(req *types.GenerateServerCertificatesRequest) (*types.GenerateServerCertificatesRequest, string) {
				req.NonceSignature = nil
				return req, "empty nonce signature"
			},
		},
		{
			name: "invalid-verification-bad-nonce-signature",
			setupFn: func(req *types.GenerateServerCertificatesRequest) (*types.GenerateServerCertificatesRequest, string) {
				req.NonceSignature[5] = 'w'
				req.NonceSignature[5] = 'h'
				req.NonceSignature[5] = 'y'
				return req, "nonce signature verification failed"
			},
		},
		{
			name: "valid-no-verification",
			setupFn: func(req *types.GenerateServerCertificatesRequest) (*types.GenerateServerCertificatesRequest, string) {
				req.NonceSignature = nil
				req.Nonce = nil
				req.SkipVerification = true
				return req, ""
			},
		},
		{
			name: "valid-overridden-common-name",
			setupFn: func(req *types.GenerateServerCertificatesRequest) (*types.GenerateServerCertificatesRequest, string) {
				req.CommonName = "foobar"
				return req, ""
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			storage := fileStorage
			req := genReq
			var wantErrContains string
			if tt.setupFn != nil {
				req, wantErrContains = tt.setupFn(proto.Clone(req).(*types.GenerateServerCertificatesRequest))
			}

			if tt.storageNil {
				storage = nil
				wantErrContains = "nil storage" // this doesn't overlap in test cases
			}

			resp, err := GenerateServerCertificates(ctx, storage, req)
			switch wantErrContains {
			case "":
				require.NoError(err)
				require.NotNil(resp)
			default:
				require.Error(err)
				assert.Contains(err.Error(), wantErrContains)
				return
			}

			assert.NotEmpty(resp.CertificatePrivateKeyPkcs8)
			assert.Equal(types.KEYTYPE_KEYTYPE_ED25519, resp.CertificatePrivateKeyType)
			assert.Len(resp.CertificateBundles, 2)
			for _, bundle := range resp.CertificateBundles {
				require.NotEmpty(bundle.CertificateDer)
				assert.NotEmpty(bundle.CaCertificateDer)
				assert.NoError(bundle.CertificateNotBefore.CheckValid())
				assert.False(bundle.CertificateNotBefore.AsTime().IsZero())
				assert.NoError(bundle.CertificateNotAfter.CheckValid())
				assert.False(bundle.CertificateNotAfter.AsTime().IsZero())

				cert, err := x509.ParseCertificate(bundle.CertificateDer)
				require.NoError(err)
				switch req.CommonName {
				case "":
					assert.Equal(nodeenrollment.CommonDnsName, cert.Subject.CommonName)
				default:
					assert.Equal(req.CommonName, cert.Subject.CommonName)
				}

				switch len(req.Nonce) {
				case 0:
				default:
					assert.Contains(cert.DNSNames, base64.RawStdEncoding.EncodeToString(req.Nonce))
				}
			}
		})
	}
}

func TestServerConfig(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fileStorage, err := file.NewFileStorage(ctx)
	require.NoError(t, err)
	t.Cleanup(fileStorage.Cleanup)

	_, err = rotation.RotateRootCertificates(ctx, fileStorage)
	require.NoError(t, err)

	// Create node credentials and have them authorized
	nodeCreds, err := registration.RegisterViaOperatorLedFlow(ctx, fileStorage, &types.OperatorLedRegistrationRequest{})
	require.NoError(t, err)

	nonceBytes := make([]byte, nodeenrollment.NonceSize)
	w, err := rand.Read(nonceBytes)
	require.NoError(t, err)
	require.EqualValues(t, w, nodeenrollment.NonceSize)

	privKey, err := x509.ParsePKCS8PrivateKey(nodeCreds.CertificatePrivateKeyPkcs8)
	require.NoError(t, err)
	nonceSigBytes, err := privKey.(crypto.Signer).Sign(rand.Reader, nonceBytes, crypto.Hash(0))
	require.NoError(t, err)

	req := &types.GenerateServerCertificatesRequest{
		CertificatePublicKeyPkix: nodeCreds.CertificatePublicKeyPkix,
		Nonce:                    nonceBytes,
		NonceSignature:           nonceSigBytes,
	}

	resp, err := GenerateServerCertificates(ctx, fileStorage, req)
	require.NoError(t, err)

	tests := []struct {
		name string
		// Return a modified node information and potentially a desired error string
		setupFn func(*types.GenerateServerCertificatesResponse) (*types.GenerateServerCertificatesResponse, string)
	}{
		{
			name: "invalid-nil",
			setupFn: func(in *types.GenerateServerCertificatesResponse) (*types.GenerateServerCertificatesResponse, string) {
				return nil, "nil input"
			},
		},
		{
			name: "invalid-nil-private-key",
			setupFn: func(in *types.GenerateServerCertificatesResponse) (*types.GenerateServerCertificatesResponse, string) {
				in.CertificatePrivateKeyPkcs8 = nil
				return in, "nil private key"
			},
		},
		{
			name: "invalid-unsupported-private-key",
			setupFn: func(in *types.GenerateServerCertificatesResponse) (*types.GenerateServerCertificatesResponse, string) {
				in.CertificatePrivateKeyType = types.KEYTYPE_KEYTYPE_X25519
				return in, "unsupported private key"
			},
		},
		{
			name: "invalid-bad-cert-bundle-length",
			setupFn: func(in *types.GenerateServerCertificatesResponse) (*types.GenerateServerCertificatesResponse, string) {
				in.CertificateBundles = in.CertificateBundles[1:]
				return in, "invalid input certificate bundles"
			},
		},
		{
			name: "valid",
			setupFn: func(in *types.GenerateServerCertificatesResponse) (*types.GenerateServerCertificatesResponse, string) {
				return in, ""
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			in := resp
			var wantErrContains string
			if tt.setupFn != nil {
				in, wantErrContains = tt.setupFn(proto.Clone(in).(*types.GenerateServerCertificatesResponse))
			}

			resp, err := ServerConfig(ctx, in)
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
			assert.Len(resp.Certificates, 2)
			for _, tlsCert := range resp.Certificates {
				assert.Len(tlsCert.Certificate, 2)
				assert.Equal(tlsCert.Certificate[0], tlsCert.Leaf.Raw)
				assert.NotEmpty(tlsCert.PrivateKey)
				assert.NotEmpty(tlsCert.Certificate[1])

				verifyOpts := x509.VerifyOptions{
					Roots:     resp.RootCAs,
					KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				}

				if tlsCert.Leaf.NotBefore.Before(time.Now()) && tlsCert.Leaf.NotAfter.After(time.Now()) {
					chains, err := tlsCert.Leaf.Verify(verifyOpts)
					require.NoError(err)
					assert.Less(0, len(chains))
				}
			}
		})
	}
}
