package registration_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"testing"
	"time"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNodeLedRegistgration_validateFetchRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fileStorage, err := file.New(ctx)
	require.NoError(t, err)
	t.Cleanup(fileStorage.Cleanup)

	roots, err := rotation.RotateRootCertificates(ctx, fileStorage)
	require.NoError(t, err)

	// This happens on the node
	nodeCreds, err := types.NewNodeCredentials(ctx, fileStorage)
	require.NoError(t, err)
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)
	keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)
	nodePubKey, err := curve25519.X25519(nodeCreds.EncryptionPrivateKeyBytes, curve25519.Basepoint)
	require.NoError(t, err)

	// Cache the decoded bundle for error checking
	unMarshal := func(t *testing.T, in *types.FetchNodeCredentialsRequest) *types.FetchNodeCredentialsInfo {
		var info types.FetchNodeCredentialsInfo
		require.NoError(t, proto.Unmarshal(in.Bundle, &info))
		return &info
	}

	reMarshalAndSign := func(t *testing.T, info *types.FetchNodeCredentialsInfo) ([]byte, []byte) {
		bundle, err := proto.Marshal(info)
		require.NoError(t, err)

		privKey, err := x509.ParsePKCS8PrivateKey(nodeCreds.CertificatePrivateKeyPkcs8)
		require.NoError(t, err)
		sigBytes, err := privKey.(crypto.Signer).Sign(nil, bundle, crypto.Hash(0))
		require.NoError(t, err)

		return bundle, sigBytes
	}

	// If testing already authorized path, add this to storage
	baseNodeInfo := &types.NodeInformation{
		Id:                       keyId,
		CertificatePublicKeyPkix: nodeCreds.CertificatePublicKeyPkix,
		CertificatePublicKeyType: nodeCreds.CertificatePrivateKeyType,
		EncryptionPublicKeyBytes: nodePubKey,
		EncryptionPublicKeyType:  nodeCreds.EncryptionPrivateKeyType,
		RegistrationNonce:        nodeCreds.RegistrationNonce,
	}

	tests := []struct {
		name string
		// Return a modified request and potentially a desired error string
		fetchSetupFn func(*testing.T, *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string)
		// Flag to set storage to nil
		storageNil bool
		// Flag to trigger an AuthorizeNode call
		runAuthorization bool
	}{
		{
			name:       "invalid-no-storage",
			storageNil: true,
		},
		{
			name: "invalid-no-req",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				return nil, "nil request"
			},
		},
		{
			name: "invalid-no-bundle",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				req.Bundle = nil
				return req, "empty bundle"
			},
		},
		{
			name: "invalid-no-bundle-sig",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				req.BundleSignature = nil
				return req, "empty bundle signature"
			},
		},
		{
			name: "invalid-no-cert-pubkey",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.CertificatePublicKeyPkix = nil
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info)
				return req, "empty node certificate public key"
			},
		},
		{
			name: "invalid-bad-cert-pubkey-type",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.CertificatePublicKeyType = types.KEYTYPE_X25519
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info)
				return req, "unsupported node certificate public key type"
			},
		},
		{
			name: "invalid-bad-cert-missing nonce",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.Nonce = nil
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info)
				return req, "empty nonce"
			},
		},
		{
			name: "invalid-bad-cert-pubkey",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.CertificatePublicKeyPkix[5] = 'w'
				info.CertificatePublicKeyPkix[10] = 'h'
				info.CertificatePublicKeyPkix[15] = 'y'
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info)
				return req, "error parsing public key"
			},
		},
		{
			name: "invalid-bad-notbefore",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.NotBefore = timestamppb.New(time.Now().Add(10 * time.Minute))
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info)
				return req, "after current time"
			},
		},
		{
			name: "invalid-bad-notafter",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.NotAfter = timestamppb.New(time.Now().Add(-10 * time.Minute))
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info)
				return req, "before current time"
			},
		},
		{
			name: "invalid-bundle-signature",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				req.BundleSignature[5] = 'w'
				req.BundleSignature[10] = 'h'
				req.BundleSignature[15] = 'y'
				return req, "signature verification failed"
			},
		},
		{
			name: "invalid-register-no-pubkey",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.EncryptionPublicKeyBytes = nil
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info)
				return req, "empty node encryption public key"
			},
		},
		{
			name: "invalid-register-bad-keytype",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.EncryptionPublicKeyType = types.KEYTYPE_ED25519
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info)
				return req, "unsupported node encryption public key type"
			},
		},
		{
			name: "invalid-register-bad-nonce",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.Nonce = info.Nonce[1:]
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info)
				return req, "invalid registration nonce"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			storage := fileStorage

			var ni *types.NodeInformation
			// Remove anything left from previous tests
			_ = storage.Remove(ctx, baseNodeInfo)

			var wantErrContains string
			fetch := fetchReq
			if tt.fetchSetupFn != nil {
				fetch, wantErrContains = tt.fetchSetupFn(t, proto.Clone(fetchReq).(*types.FetchNodeCredentialsRequest))
			}

			if tt.storageNil {
				storage = nil
				wantErrContains = "nil storage" // this doesn't overlap in test cases
			}

			if tt.runAuthorization {
				// We have to _actually_ authorize the node here to populate things we need
				_, err := registration.AuthorizeNode(ctx, storage, fetchReq)
				require.NoError(err)
			}

			resp, err := registration.FetchNodeCredentials(ctx, storage, fetch)
			switch wantErrContains {
			case "":
				require.NoError(err)
				require.NotNil(resp)
			default:
				require.Error(err)
				assert.Contains(err.Error(), wantErrContains)
				return
			}

			// Now run other checks depending on which path we took
			checkNodeInfo := &types.NodeInformation{Id: baseNodeInfo.Id}
			require.NotNil(resp.EncryptedNodeCredentials)
			require.NotNil(resp.EncryptedNodeCredentialsSignature)
			require.NotNil(resp.ServerEncryptionPublicKeyBytes)
			require.Equal(types.KEYTYPE_X25519, resp.ServerEncryptionPublicKeyType)
			require.True(resp.Authorized)

			// Now check the signature
			caKey, err := x509.ParsePKIXPublicKey(roots.Current.PublicKeyPkix)
			require.NoError(err)
			require.True(ed25519.Verify(caKey.(ed25519.PublicKey), resp.EncryptedNodeCredentials, resp.EncryptedNodeCredentialsSignature))

			// Now decrypt
			require.NoError(storage.Load(ctx, checkNodeInfo))
			require.NotNil(checkNodeInfo)
			var receivedNodeCreds types.NodeCredentials
			require.NoError(nodeenrollment.DecryptMessage(ctx, checkNodeInfo.Id, resp.EncryptedNodeCredentials, checkNodeInfo, &receivedNodeCreds))
			assert.NotEmpty(receivedNodeCreds.ServerEncryptionPublicKeyBytes)
			assert.Equal(types.KEYTYPE_X25519, receivedNodeCreds.ServerEncryptionPublicKeyType)
			assert.Equal(ni.RegistrationNonce, receivedNodeCreds.RegistrationNonce)
			assert.Len(receivedNodeCreds.CertificateBundles, 2) // Won't go through them here, have one that in other tests
		})
	}
}

func TestNodeLedRegistration_FetchNodeCredentials(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fileStorage, err := file.New(ctx)
	require.NoError(t, err)
	t.Cleanup(fileStorage.Cleanup)

	roots, err := rotation.RotateRootCertificates(ctx, fileStorage)
	require.NoError(t, err)

	// This happens on the node
	nodeCreds, err := types.NewNodeCredentials(ctx, fileStorage)
	require.NoError(t, err)
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)
	keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)
	nodePubKey, err := curve25519.X25519(nodeCreds.EncryptionPrivateKeyBytes, curve25519.Basepoint)
	require.NoError(t, err)

	// If testing already authorized path, add this to storage
	baseNodeInfo := &types.NodeInformation{
		Id:                       keyId,
		CertificatePublicKeyPkix: nodeCreds.CertificatePublicKeyPkix,
		CertificatePublicKeyType: nodeCreds.CertificatePrivateKeyType,
		EncryptionPublicKeyBytes: nodePubKey,
		EncryptionPublicKeyType:  nodeCreds.EncryptionPrivateKeyType,
		RegistrationNonce:        nodeCreds.RegistrationNonce,
	}

	tests := []struct {
		name string
		// Return a modified node information and potentially a desired error string
		nodeInfoSetupFn func(*types.NodeInformation) *types.NodeInformation
		// Flag to trigger an AuthorizeNode call
		runAuthorization bool
	}{
		{
			name: "valid-authorized",
			nodeInfoSetupFn: func(in *types.NodeInformation) *types.NodeInformation {
				return in
			},
			runAuthorization: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			storage := fileStorage

			var ni *types.NodeInformation
			if tt.nodeInfoSetupFn != nil {
				ni = tt.nodeInfoSetupFn(proto.Clone(baseNodeInfo).(*types.NodeInformation))
			} else {
				_ = storage.Remove(ctx, baseNodeInfo)
			}

			if tt.runAuthorization {
				// We have to _actually_ authorize the node here to populate things we need
				_, err := registration.AuthorizeNode(ctx, storage, fetchReq)
				require.NoError(err)
			}

			resp, err := registration.FetchNodeCredentials(ctx, storage, fetchReq)
			require.NoError(err)
			require.NotNil(resp)

			// Now run other checks depending on which path we took
			checkNodeInfo := &types.NodeInformation{Id: baseNodeInfo.Id}
			require.NotNil(resp.EncryptedNodeCredentials)
			require.NotNil(resp.EncryptedNodeCredentialsSignature)
			require.NotNil(resp.ServerEncryptionPublicKeyBytes)
			require.Equal(types.KEYTYPE_X25519, resp.ServerEncryptionPublicKeyType)
			require.True(resp.Authorized)

			// Now check the signature
			caKey, err := x509.ParsePKIXPublicKey(roots.Current.PublicKeyPkix)
			require.NoError(err)
			require.True(ed25519.Verify(caKey.(ed25519.PublicKey), resp.EncryptedNodeCredentials, resp.EncryptedNodeCredentialsSignature))

			// Now decrypt
			require.NoError(storage.Load(ctx, checkNodeInfo))
			require.NotNil(checkNodeInfo)
			var receivedNodeCreds types.NodeCredentials
			require.NoError(nodeenrollment.DecryptMessage(ctx, checkNodeInfo.Id, resp.EncryptedNodeCredentials, checkNodeInfo, &receivedNodeCreds))
			assert.NotEmpty(receivedNodeCreds.ServerEncryptionPublicKeyBytes)
			assert.Equal(types.KEYTYPE_X25519, receivedNodeCreds.ServerEncryptionPublicKeyType)
			assert.Equal(ni.RegistrationNonce, receivedNodeCreds.RegistrationNonce)
			assert.Len(receivedNodeCreds.CertificateBundles, 2) // Won't go through them here, have one that in other tests
		})
	}
}

func TestNodeLedRegistration_AuthorizeNode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fileStorage, err := file.New(ctx)
	require.NoError(t, err)
	t.Cleanup(fileStorage.Cleanup)

	_, err = rotation.RotateRootCertificates(ctx, fileStorage)
	require.NoError(t, err)

	// This happens on the node
	nodeCreds, err := types.NewNodeCredentials(ctx, fileStorage)
	require.NoError(t, err)
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)
	keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)
	nodePubKey, err := curve25519.X25519(nodeCreds.EncryptionPrivateKeyBytes, curve25519.Basepoint)
	require.NoError(t, err)

	structMap := map[string]interface{}{"foo": "bar"}
	state, err := structpb.NewStruct(structMap)
	require.NoError(t, err)

	// Add in node information to storage so we have a key to use
	nodeInfo := &types.NodeInformation{
		Id:                       keyId,
		CertificatePublicKeyPkix: nodeCreds.CertificatePublicKeyPkix,
		CertificatePublicKeyType: nodeCreds.CertificatePrivateKeyType,
		EncryptionPublicKeyBytes: nodePubKey,
		EncryptionPublicKeyType:  nodeCreds.EncryptionPrivateKeyType,
		RegistrationNonce:        nodeCreds.RegistrationNonce,
		State:                    state,
	}

	tests := []struct {
		name string
		// Flag to insert node information in advance
		prepopulatedNodeInfo bool
		// Flag to set storage to nil
		storageNil bool
	}{
		{
			name:       "invalid-no-storage",
			storageNil: true,
		},
		{
			name: "valid",
		},
		// Leave this after "valid" so it checks when it's already there
		{
			name:                 "invalid-already-authorized",
			prepopulatedNodeInfo: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			storage := fileStorage
			var wantErrContains string

			if tt.storageNil {
				storage = nil
				wantErrContains = "nil storage" // this doesn't overlap in test cases
			}

			if tt.prepopulatedNodeInfo {
				wantErrContains = "existing node"
			}

			_, err := registration.AuthorizeNode(ctx, storage, fetchReq)
			switch wantErrContains {
			case "":
				require.NoError(err)
			default:
				require.Error(err)
				assert.Contains(err.Error(), wantErrContains)
				return
			}

			checkNodeInfo := &types.NodeInformation{Id: nodeInfo.Id}
			require.NoError(storage.Load(ctx, checkNodeInfo))
			require.NotNil(checkNodeInfo)
			assert.Equal(nodeInfo.Id, checkNodeInfo.Id)
			assert.NotEmpty(checkNodeInfo.CertificatePublicKeyPkix)
			assert.Equal(types.KEYTYPE_ED25519, checkNodeInfo.CertificatePublicKeyType)
			assert.Len(checkNodeInfo.CertificateBundles, 2)
			for _, bundle := range checkNodeInfo.CertificateBundles {
				assert.NotEmpty(bundle.CertificateDer)
				assert.NotEmpty(bundle.CaCertificateDer)
				assert.NoError(bundle.CertificateNotBefore.CheckValid())
				assert.False(bundle.CertificateNotBefore.AsTime().IsZero())
				assert.NoError(bundle.CertificateNotAfter.CheckValid())
				assert.False(bundle.CertificateNotAfter.AsTime().IsZero())
			}
			assert.NotEmpty(checkNodeInfo.EncryptionPublicKeyBytes)
			assert.Equal(types.KEYTYPE_X25519, checkNodeInfo.EncryptionPublicKeyType)
			assert.NotEmpty(checkNodeInfo.ServerEncryptionPrivateKeyBytes)
			assert.Equal(types.KEYTYPE_X25519, checkNodeInfo.ServerEncryptionPrivateKeyType)
			assert.Len(checkNodeInfo.RegistrationNonce, nodeenrollment.NonceSize)
		})
	}
}
