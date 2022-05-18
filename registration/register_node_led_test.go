package registration

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"testing"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

// AuthorizeNode test is first because we want to call AuthorizeNode in the test
// for FetchNodeCredentials, so it is a bit cleaner ordering
func TestNodeLedRegistration_AuthorizeNode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fileStorage, err := file.NewFileStorage(ctx)
	require.NoError(t, err)
	t.Cleanup(fileStorage.Cleanup)

	_, err = rotation.RotateRootCertificates(ctx, fileStorage)
	require.NoError(t, err)

	// This happens on the node
	nodeCreds, err := types.NewNodeCredentials(ctx, fileStorage)
	require.NoError(t, err)
	keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)
	nodePubKey, err := curve25519.X25519(nodeCreds.EncryptionPrivateKeyBytes, curve25519.Basepoint)
	require.NoError(t, err)

	// Add in node information to storage so we have a key to use
	nodeInfo := &types.NodeInformation{
		Id:                       keyId,
		CertificatePublicKeyPkix: nodeCreds.CertificatePublicKeyPkix,
		CertificatePublicKeyType: nodeCreds.CertificatePrivateKeyType,
		EncryptionPublicKeyBytes: nodePubKey,
		EncryptionPublicKeyType:  nodeCreds.EncryptionPrivateKeyType,
		RegistrationNonce:        nodeCreds.RegistrationNonce,
		FirstSeen:                timestamppb.Now(),
	}

	tests := []struct {
		name string
		// Return a modified node information and potentially a desired error string
		setupFn func(*types.NodeInformation) (*types.NodeInformation, string)
		// Flag to set storage to nil
		storageNil bool
		// Flag to set key ID to empty
		keyIdEmpty bool
	}{
		{
			name:       "invalid-no-storage",
			storageNil: true,
		},
		{
			name:       "invalid-no-key-id",
			keyIdEmpty: true,
		},
		{
			name: "invalid-already-authorized",
			setupFn: func(nodeInfo *types.NodeInformation) (*types.NodeInformation, string) {
				nodeInfo.Authorized = true
				return nodeInfo, "already authorized"
			},
		},
		{
			name: "valid",
			setupFn: func(nodeInfo *types.NodeInformation) (*types.NodeInformation, string) {
				return nodeInfo, ""
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)
			ni := nodeInfo

			storage := fileStorage
			var wantErrContains string
			if tt.setupFn != nil {
				ni, wantErrContains = tt.setupFn(proto.Clone(ni).(*types.NodeInformation))
			}
			require.NoError(ni.Store(ctx, storage))

			keyId := ni.Id
			if tt.keyIdEmpty {
				keyId = ""
				wantErrContains = "empty key id" // this doesn't overlap in test cases
			}
			if tt.storageNil {
				storage = nil
				wantErrContains = "nil storage" // this doesn't overlap in test cases
			}

			err = AuthorizeNode(ctx, storage, keyId)
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
			assert.Equal(types.KEYTYPE_KEYTYPE_ED25519, checkNodeInfo.CertificatePublicKeyType)
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
			assert.Equal(types.KEYTYPE_KEYTYPE_X25519, checkNodeInfo.EncryptionPublicKeyType)
			assert.NotEmpty(checkNodeInfo.ServerEncryptionPrivateKeyBytes)
			assert.Equal(types.KEYTYPE_KEYTYPE_X25519, checkNodeInfo.ServerEncryptionPrivateKeyType)
			assert.Len(checkNodeInfo.RegistrationNonce, nodeenrollment.NonceSize)
			assert.True(checkNodeInfo.FirstSeen.IsValid())
			assert.False(checkNodeInfo.FirstSeen.AsTime().IsZero())
			assert.True(checkNodeInfo.Authorized)
		})
	}
}

func TestNodeLedRegistration_FetchNodeCredentials(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fileStorage, err := file.NewFileStorage(ctx)
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
		FirstSeen:                timestamppb.Now(),
	}

	tests := []struct {
		name string
		// Return a modified request and potentially a desired error string
		fetchSetupFn func(*testing.T, *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string)
		// Return a modified node information and potentially a desired error string
		nodeInfoSetupFn func(*types.NodeInformation) *types.NodeInformation
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
				info.CertificatePublicKeyType = types.KEYTYPE_KEYTYPE_X25519
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
				info.EncryptionPublicKeyType = types.KEYTYPE_KEYTYPE_ED25519
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
		{
			name: "valid-register",
		},
		{
			name: "valid-already-registered-not-authorized",
			nodeInfoSetupFn: func(in *types.NodeInformation) *types.NodeInformation {
				return in
			},
		},
		{
			name: "invalid-already-registered-authorized-but-mismatched-nonce",
			nodeInfoSetupFn: func(in *types.NodeInformation) *types.NodeInformation {
				in.Authorized = true
				in.RegistrationNonce = in.RegistrationNonce[1:]
				return in
			},
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				return req, "mismatched nonces"
			},
		},
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
				require.NoError(ni.Store(ctx, storage))
			} else {
				_ = storage.Remove(ctx, baseNodeInfo)
			}

			// Verify that if we don't have information stored we don't actually
			// see it in storage
			if ni == nil {
				_, err := types.LoadNodeInformation(ctx, storage, baseNodeInfo.Id)
				require.Contains(err.Error(), nodeenrollment.ErrNotFound.Error())
			}

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
				require.NoError(AuthorizeNode(ctx, storage, baseNodeInfo.Id))
			}

			resp, err := FetchNodeCredentials(ctx, storage, fetch)
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
			switch {
			case ni == nil:
				// Register case -- we had no node info, should now see info but unauthorized
				require.NoError(storage.Load(ctx, checkNodeInfo))
				require.NotNil(checkNodeInfo)
				assert.Equal(baseNodeInfo.Id, checkNodeInfo.Id)
				assert.NotEmpty(checkNodeInfo.CertificatePublicKeyPkix)
				assert.Equal(types.KEYTYPE_KEYTYPE_ED25519, checkNodeInfo.CertificatePublicKeyType)
				assert.NotEmpty(checkNodeInfo.EncryptionPublicKeyBytes)
				assert.Equal(types.KEYTYPE_KEYTYPE_X25519, checkNodeInfo.EncryptionPublicKeyType)
				assert.NotEmpty(checkNodeInfo.RegistrationNonce)
				assert.True(checkNodeInfo.FirstSeen.IsValid())
				assert.False(checkNodeInfo.FirstSeen.AsTime().IsZero())
				assert.False(checkNodeInfo.Authorized)

			case !ni.Authorized:
				// We were already there but not authorized, should still be unauthorized
				assert.False(checkNodeInfo.Authorized)

			default:
				require.NotNil(resp.EncryptedNodeCredentials)
				require.NotNil(resp.EncryptedNodeCredentialsSignature)
				require.NotNil(resp.ServerEncryptionPublicKeyBytes)
				require.Equal(types.KEYTYPE_KEYTYPE_X25519, resp.ServerEncryptionPublicKeyType)
				require.True(resp.Authorized)

				// Now check the signature
				caKey, err := x509.ParsePKIXPublicKey(roots.Current.PublicKeyPkix)
				require.NoError(err)
				require.True(ed25519.Verify(caKey.(ed25519.PublicKey), resp.EncryptedNodeCredentials, resp.EncryptedNodeCredentialsSignature))

				// Now decrypt
				var receivedNodeCreds types.NodeCredentials
				require.NoError(nodeenrollment.DecryptMessage(ctx, checkNodeInfo.Id, resp.EncryptedNodeCredentials, checkNodeInfo, &receivedNodeCreds))
				assert.NotEmpty(receivedNodeCreds.ServerEncryptionPublicKeyBytes)
				assert.Equal(types.KEYTYPE_KEYTYPE_X25519, receivedNodeCreds.ServerEncryptionPublicKeyType)
				assert.Equal(ni.RegistrationNonce, receivedNodeCreds.RegistrationNonce)
				assert.Len(receivedNodeCreds.CertificateBundles, 2) // Won't go through them here, have one that in other tests
			}
		})
	}
}
