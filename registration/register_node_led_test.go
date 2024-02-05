// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package registration_test

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"testing"
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/inmem"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestValidateFetchRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(t, err)

	roots, err := rotation.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	// This happens on the node
	nodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)
	keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)
	nodePrivKey, err := ecdh.X25519().NewPrivateKey(nodeCreds.EncryptionPrivateKeyBytes)
	require.NoError(t, err)
	nodePubKey := nodePrivKey.PublicKey()

	// Also create a server-led value for that path
	_, activationToken, err := registration.CreateServerLedActivationToken(ctx, storage, &types.ServerLedRegistrationRequest{})
	require.NoError(t, err)
	serverLedNodeCreds, err := types.NewNodeCredentials(ctx, storage, nodeenrollment.WithActivationToken(activationToken))
	require.NoError(t, err)
	serverLedFetchReq, err := serverLedNodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)
	serverLedKeyId, err := nodeenrollment.KeyIdFromPkix(serverLedNodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)

	// And, create something for the wrapping flow
	registrationWrapper := wrapping.NewTestWrapper([]byte("foobar"))
	applicationSpecificParamsMap := map[string]any{"foo": "bar"}
	mapOpt, err := structpb.NewStruct(applicationSpecificParamsMap)
	require.NoError(t, err)
	wrappingNodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)
	wrappingFetchReq, err := wrappingNodeCreds.CreateFetchNodeCredentialsRequest(ctx,
		nodeenrollment.WithRegistrationWrapper(registrationWrapper),
		nodeenrollment.WithWrappingRegistrationFlowApplicationSpecificParams(mapOpt),
	)
	require.NoError(t, err)
	wrappingKeyId, err := nodeenrollment.KeyIdFromPkix(wrappingNodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)
	// Create and register an "interim" node that is used for wrapping for the rewrapping test
	interimNodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)
	interimReq, err := interimNodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)
	_, err = registration.AuthorizeNode(ctx, storage, interimReq)
	require.NoError(t, err)
	interimFetchResp, err := registration.FetchNodeCredentials(ctx, storage, interimReq)
	require.NoError(t, err)
	interimNodeCreds, err = interimNodeCreds.HandleFetchNodeCredentialsResponse(ctx, storage, interimFetchResp)
	require.NoError(t, err)

	// Cache the decoded bundle for error checking
	unMarshal := func(t *testing.T, in *types.FetchNodeCredentialsRequest) *types.FetchNodeCredentialsInfo {
		var info types.FetchNodeCredentialsInfo
		require.NoError(t, proto.Unmarshal(in.Bundle, &info))
		return &info
	}

	reMarshalAndSign := func(t *testing.T, info *types.FetchNodeCredentialsInfo, creds *types.NodeCredentials) ([]byte, []byte) {
		bundle, err := proto.Marshal(info)
		require.NoError(t, err)

		privKey, err := x509.ParsePKCS8PrivateKey(creds.CertificatePrivateKeyPkcs8)
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
		EncryptionPublicKeyBytes: nodePubKey.Bytes(),
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
		// Flag to indicate an expected authorization error
		wantAuthzErrContains string
		// checkNodeInfoIdOverride allows overriding the id used in the load for
		// the check node info
		checkNodeInfoIdOverride string
		// Options to pass to the fetch function
		fetchFnOpts []nodeenrollment.Option
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
			name: "invalid-empty-nonce",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.Nonce = nil
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info, nodeCreds)
				return req, "empty nonce"
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
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info, nodeCreds)
				return req, "empty node certificate public key"
			},
		},
		{
			name: "invalid-bad-cert-pubkey-type",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.CertificatePublicKeyType = types.KEYTYPE_X25519
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info, nodeCreds)
				return req, "unsupported node certificate public key type"
			},
		},
		{
			name: "invalid-bad-cert-pubkey",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.CertificatePublicKeyPkix[5] = 'w'
				info.CertificatePublicKeyPkix[10] = 'h'
				info.CertificatePublicKeyPkix[15] = 'y'
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info, nodeCreds)
				return req, "error parsing public key"
			},
		},
		{
			name: "invalid-bad-notbefore",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.NotBefore = timestamppb.New(time.Now().Add(10 * time.Minute))
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info, nodeCreds)
				return req, "after current time"
			},
		},
		{
			name: "invalid-bad-notafter",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.NotAfter = timestamppb.New(time.Now().Add(-10 * time.Minute))
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info, nodeCreds)
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
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info, nodeCreds)
				return req, "empty node encryption public key"
			},
		},
		{
			name: "invalid-register-bad-keytype",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.EncryptionPublicKeyType = types.KEYTYPE_ED25519
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info, nodeCreds)
				return req, "unsupported node encryption public key type"
			},
		},
		{
			name: "invalid-register-bad-nonce",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, req)
				info.Nonce = info.Nonce[1:]
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info, nodeCreds)
				return req, "cannot parse invalid wire-format data"
			},
		},
		{
			name: "invalid-attempt-to-authorize-with-server-led",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				return serverLedFetchReq, ""
			},
			runAuthorization:     true,
			wantAuthzErrContains: "server-led activation tokens cannot be used",
		},
		{
			name:             "valid",
			runAuthorization: true,
		},
		{
			name: "valid-server-led",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				return serverLedFetchReq, ""
			},
			checkNodeInfoIdOverride: serverLedKeyId,
		},
		{
			name: "wrapping-flow-no-wrapper",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				return wrappingFetchReq, "no registration wrapper provided"
			},
		},
		{
			name: "invalid-wrapping-flow-bad-data",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				info := unMarshal(t, wrappingFetchReq)
				info.WrappedRegistrationInfo = []byte("foobar") // info.WrappedRegistrationInfo[1:]
				req.Bundle, req.BundleSignature = reMarshalAndSign(t, info, wrappingNodeCreds)
				return req, "error unmarshaling encrypted wrapped registration info"
			},
			fetchFnOpts: []nodeenrollment.Option{
				nodeenrollment.WithRegistrationWrapper(registrationWrapper),
			},
		},
		{
			name: "valid-wrapping-flow-normal",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				return wrappingFetchReq, ""
			},
			checkNodeInfoIdOverride: wrappingKeyId,
			fetchFnOpts: []nodeenrollment.Option{
				nodeenrollment.WithRegistrationWrapper(registrationWrapper),
			},
		},
		{
			name: "valid-wrapping-flow-rewrapped",
			fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
				fetch := proto.Clone(wrappingFetchReq).(*types.FetchNodeCredentialsRequest)
				info := unMarshal(t, fetch)
				regInfo, err := registration.DecryptWrappedRegistrationInfo(
					ctx,
					info,
					nodeenrollment.WithRegistrationWrapper(registrationWrapper),
				)
				require.NoError(t, err)
				fetch.RewrappingKeyId, err = nodeenrollment.KeyIdFromPkix(interimNodeCreds.CertificatePublicKeyPkix)
				require.NoError(t, err)
				fetch.RewrappedWrappingRegistrationFlowInfo, err = nodeenrollment.EncryptMessage(ctx, regInfo, interimNodeCreds)
				require.NoError(t, err)
				return fetch, ""
			},
			checkNodeInfoIdOverride: wrappingKeyId,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require, assert := require.New(t), assert.New(t)

			// Remove anything left from previous tests
			_ = storage.Remove(ctx, baseNodeInfo)

			localStorage := storage

			var wantErrContains string
			fetch := fetchReq
			if tt.fetchSetupFn != nil {
				fetch, wantErrContains = tt.fetchSetupFn(t, proto.Clone(fetchReq).(*types.FetchNodeCredentialsRequest))
			}

			if tt.storageNil {
				localStorage = nil
				wantErrContains = "nil storage" // this doesn't overlap in test cases
			}

			if tt.runAuthorization {
				// We have to _actually_ authorize the node here to populate things we need
				_, err := registration.AuthorizeNode(ctx, localStorage, fetch)
				switch tt.wantAuthzErrContains {
				case "":
					require.NoError(err)
				default:
					require.Error(err)
					assert.Contains(err.Error(), tt.wantAuthzErrContains)
					return
				}
			}

			resp, err := registration.FetchNodeCredentials(ctx, localStorage, fetch, tt.fetchFnOpts...)
			switch wantErrContains {
			case "":
				require.NoError(err)
				require.NotNil(resp)
			default:
				require.Error(err)
				assert.Contains(err.Error(), wantErrContains)
				return
			}

			// Now run checks on valid paths
			checkNodeInfoId := baseNodeInfo.Id
			if tt.checkNodeInfoIdOverride != "" {
				checkNodeInfoId = tt.checkNodeInfoIdOverride
			}
			checkNodeInfo := &types.NodeInformation{Id: checkNodeInfoId}
			require.NotNil(resp.EncryptedNodeCredentials)
			require.NotNil(resp.EncryptedNodeCredentialsSignature)
			require.NotNil(resp.ServerEncryptionPublicKeyBytes)
			require.Equal(types.KEYTYPE_X25519, resp.ServerEncryptionPublicKeyType)

			// Now check the signature
			caKey, err := x509.ParsePKIXPublicKey(roots.Current.PublicKeyPkix)
			require.NoError(err)
			require.True(ed25519.Verify(caKey.(ed25519.PublicKey), resp.EncryptedNodeCredentials, resp.EncryptedNodeCredentialsSignature))

			// Now decrypt
			require.NoError(localStorage.Load(ctx, checkNodeInfo))
			require.NotNil(checkNodeInfo)
			var receivedNodeCreds types.NodeCredentials
			require.NoError(nodeenrollment.DecryptMessage(ctx, resp.EncryptedNodeCredentials, checkNodeInfo, &receivedNodeCreds))
			assert.NotEmpty(receivedNodeCreds.ServerEncryptionPublicKeyBytes)
			assert.Equal(types.KEYTYPE_X25519, receivedNodeCreds.ServerEncryptionPublicKeyType)
			assert.Len(receivedNodeCreds.CertificateBundles, 2) // Won't go through them here, have one that in other tests

			fetchInfo := unMarshal(t, fetch)
			assert.Equal(fetchInfo.Nonce, receivedNodeCreds.RegistrationNonce)
		})
	}
}

func TestNodeLedRegistration_FetchNodeCredentials(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(t, err)

	roots, err := rotation.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	// This happens on the node
	nodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx)
	require.NoError(t, err)
	keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)
	nodePrivKey, err := ecdh.X25519().NewPrivateKey(nodeCreds.EncryptionPrivateKeyBytes)
	require.NoError(t, err)
	nodePubKey := nodePrivKey.PublicKey()

	// If testing already authorized path, add this to storage
	baseNodeInfo := &types.NodeInformation{
		Id:                       keyId,
		CertificatePublicKeyPkix: nodeCreds.CertificatePublicKeyPkix,
		CertificatePublicKeyType: nodeCreds.CertificatePrivateKeyType,
		EncryptionPublicKeyBytes: nodePubKey.Bytes(),
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

			// Now check the signature
			caKey, err := x509.ParsePKIXPublicKey(roots.Current.PublicKeyPkix)
			require.NoError(err)
			require.True(ed25519.Verify(caKey.(ed25519.PublicKey), resp.EncryptedNodeCredentials, resp.EncryptedNodeCredentialsSignature))

			// Now decrypt
			require.NoError(storage.Load(ctx, checkNodeInfo))
			require.NotNil(checkNodeInfo)
			var receivedNodeCreds types.NodeCredentials
			require.NoError(nodeenrollment.DecryptMessage(ctx, resp.EncryptedNodeCredentials, checkNodeInfo, &receivedNodeCreds))
			assert.NotEmpty(receivedNodeCreds.ServerEncryptionPublicKeyBytes)
			assert.Equal(types.KEYTYPE_X25519, receivedNodeCreds.ServerEncryptionPublicKeyType)
			assert.Equal(ni.RegistrationNonce, receivedNodeCreds.RegistrationNonce)
			assert.Len(receivedNodeCreds.CertificateBundles, 2) // Won't go through them here, have one that in other tests
		})
	}
}
