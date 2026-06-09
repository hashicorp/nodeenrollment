// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package registration_test

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/inmem"
	"github.com/hashicorp/nodeenrollment/types"
	nodetesting "github.com/hashicorp/nodeenrollment/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestValidateFetchRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

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

	for _, kt := range nodetesting.TestKeyTypeVariants() {
		t.Run(kt.Name, func(t *testing.T) {
			t.Parallel()

			storage, err := inmem.New(ctx)
			require.NoError(t, err)

			_, err = rotation.RotateRootCertificates(ctx, storage)
			require.NoError(t, err)

			// This happens on the node
			nodeCreds, err := types.NewNodeCredentials(ctx, storage, kt.Opts...)
			require.NoError(t, err)
			// authzReq includes the challenge (used for AuthorizeNode)
			authzReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
			require.NoError(t, err)
			// fetchReq omits the challenge from the bundle (used for FetchNodeCredentials)
			fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage, nodeenrollment.WithoutRegistrationChallenge(true))
			require.NoError(t, err)
			keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
			require.NoError(t, err)

			// For X25519, extract the public key bytes for baseNodeInfo
			var encPublicKeyBytes []byte
			if kt.KeyType == types.KEYTYPE_X25519 {
				nodePrivKey, err := ecdh.X25519().NewPrivateKey(nodeCreds.EncryptionPrivateKeyBytes)
				require.NoError(t, err)
				encPublicKeyBytes = nodePrivKey.PublicKey().Bytes()
			}

			// Create a server-led activation token for server-led tests
			_, serverLedActivationToken, err := registration.CreateServerLedActivationToken(ctx, storage, &types.ServerLedRegistrationRequest{}, kt.Opts...)
			require.NoError(t, err)
			serverLedNodeCreds, err := types.NewNodeCredentials(ctx, storage, kt.Opts...)
			require.NoError(t, err)
			serverLedFetchReq, err := serverLedNodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage,
				nodeenrollment.WithActivationToken(serverLedActivationToken),
			)
			require.NoError(t, err)
			serverLedKeyId, err := nodeenrollment.KeyIdFromPkix(serverLedNodeCreds.CertificatePublicKeyPkix)
			require.NoError(t, err)

			// And, create something for the wrapping flow
			var x25519Opts []nodeenrollment.Option
			if kt.KeyType == types.KEYTYPE_X25519 {
				x25519Opts = []nodeenrollment.Option{nodeenrollment.WithEncryptionPrivateKeyType(uint(types.KEYTYPE_X25519))}
			}
			registrationWrapper := wrapping.NewTestWrapper([]byte("foobar"))
			applicationSpecificParamsMap := map[string]any{"foo": "bar"}
			mapOpt, err := structpb.NewStruct(applicationSpecificParamsMap)
			require.NoError(t, err)
			wrappingNodeCreds, err := types.NewNodeCredentials(ctx, storage, x25519Opts...)
			require.NoError(t, err)
			wrappingFetchReq, err := wrappingNodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage,
				nodeenrollment.WithRegistrationWrapper(registrationWrapper),
				nodeenrollment.WithWrappingRegistrationFlowApplicationSpecificParams(mapOpt),
			)
			require.NoError(t, err)
			wrappingKeyId, err := nodeenrollment.KeyIdFromPkix(wrappingNodeCreds.CertificatePublicKeyPkix)
			require.NoError(t, err)
			// Create and register an "interim" node used for the rewrapping test
			interimNodeCreds, err := types.NewNodeCredentials(ctx, storage, x25519Opts...)
			require.NoError(t, err)
			interimAuthzReq, err := interimNodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
			require.NoError(t, err)
			_, err = registration.AuthorizeNode(ctx, storage, interimAuthzReq)
			require.NoError(t, err)
			interimFetchReq, err := interimNodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage, nodeenrollment.WithoutRegistrationChallenge(true))
			require.NoError(t, err)
			interimFetchResp, err := registration.FetchNodeCredentials(ctx, storage, interimFetchReq)
			require.NoError(t, err)
			interimNodeCreds, err = interimNodeCreds.HandleFetchNodeCredentialsResponse(ctx, storage, interimFetchResp)
			require.NoError(t, err)

			// If testing already authorized path, add this to storage
			baseNodeInfo := &types.NodeInformation{
				Id:                       keyId,
				CertificatePublicKeyPkix: nodeCreds.CertificatePublicKeyPkix,
				CertificatePublicKeyType: nodeCreds.CertificatePrivateKeyType,
				EncryptionPublicKeyBytes: encPublicKeyBytes,
				EncryptionPublicKeyType:  nodeCreds.EncryptionPrivateKeyType,
				RegistrationNonce:        nodeCreds.RegistrationNonce,
			}

			// Build the key-type-specific "no pubkey" test case
			var noPubKeyTestName string
			var noPubKeyTestFn func(*testing.T, *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string)
			if kt.KeyType == types.KEYTYPE_MLKEM1024 {
				noPubKeyTestName = "invalid-register-no-mlkem-encap-key"
				noPubKeyTestFn = func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
					info := unMarshal(t, req)
					info.MlkemParameters = nil
					req.Bundle, req.BundleSignature = reMarshalAndSign(t, info, nodeCreds)
					return req, "mlkem parameters are nil"
				}
			} else {
				noPubKeyTestName = "invalid-register-no-pubkey"
				noPubKeyTestFn = func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
					info := unMarshal(t, req)
					info.EncryptionPublicKeyBytes = nil
					req.Bundle, req.BundleSignature = reMarshalAndSign(t, info, nodeCreds)
					return req, "empty node encryption public key"
				}
			}

			tests := []struct {
				name string
				// Return a modified request and potentially a desired error string. The
				// request passed to the function is a clone of fetchReq.
				fetchSetupFn func(*testing.T, *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string)
				// authzReqOverride, if set, is the request passed to AuthorizeNode
				// instead of the one returned by fetchSetupFn. Useful when auth and
				// fetch must differ.
				authzReqOverride *types.FetchNodeCredentialsRequest
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
				// If true, verify that the encrypted challenge is in the decrypted response
				wantEncryptedChallenge bool
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
					name: "invalid-empty-nonce-and-no-registration-challenge",
					fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
						info := unMarshal(t, authzReq) // use authzReq as base (has challenge)
						info.Nonce = nil
						info.RegistrationChallenge = nil
						req.Bundle, req.BundleSignature = reMarshalAndSign(t, info, nodeCreds)
						return req, ""
					},
					runAuthorization:     true,
					wantAuthzErrContains: "must contain a nonce or a registration challenge",
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
					name:         noPubKeyTestName,
					fetchSetupFn: noPubKeyTestFn,
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
						info.EncryptedRegistrationChallenge = []byte("foobar")
						info.Nonce = []byte("foobar")
						req.Bundle, req.BundleSignature = reMarshalAndSign(t, info, nodeCreds)
						return req, "cannot parse invalid wire-format data"
					},
				},
				{
					// For MLKEM1024: a fetch request that declares X25519 encryption
					// (which passes validateFetchRequestCommon) must be rejected by
					// FetchNodeCredentials when the stored node uses MLKEM1024.
					// For X25519: the unchanged fetch request succeeds after authorization.
					name:             "invalid-mlkem-fetch-declares-x25519-key-type",
					authzReqOverride: authzReq,
					runAuthorization: true,
					fetchSetupFn: func(t *testing.T, req *types.FetchNodeCredentialsRequest) (*types.FetchNodeCredentialsRequest, string) {
						if kt.KeyType != types.KEYTYPE_MLKEM1024 {
							return req, ""
						}
						x25519Key, err := ecdh.X25519().GenerateKey(rand.Reader)
						require.NoError(t, err)
						info := unMarshal(t, req)
						info.EncryptionPublicKeyType = types.KEYTYPE_X25519
						info.EncryptionPublicKeyBytes = x25519Key.PublicKey().Bytes()
						info.MlkemParameters = nil
						req.Bundle, req.BundleSignature = reMarshalAndSign(t, info, nodeCreds)
						return req, "mismatched encryption key types"
					},
				},
				{
					// Node-led new protocol: authorize with challenge in request, fetch
					// without challenge, expect encrypted challenge in response.
					name:                   "valid-node-led",
					authzReqOverride:       authzReq,
					runAuthorization:       true,
					wantEncryptedChallenge: true,
				},
				{
					// Server-led new protocol: no prior AuthorizeNode needed; token is
					// the authorization.
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
						info.WrappedRegistrationInfo = []byte("foobar")
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
					fetch := proto.Clone(fetchReq).(*types.FetchNodeCredentialsRequest)
					if tt.fetchSetupFn != nil {
						fetch, wantErrContains = tt.fetchSetupFn(t, fetch)
					}

					if tt.storageNil {
						localStorage = nil
						wantErrContains = "nil storage" // this doesn't overlap in test cases
					}

					if tt.runAuthorization {
						authzRequest := fetch
						if tt.authzReqOverride != nil {
							authzRequest = tt.authzReqOverride
						}
						_, err := registration.AuthorizeNode(ctx, localStorage, authzRequest)
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

					// Load to determine key type
					require.NoError(localStorage.Load(ctx, checkNodeInfo))
					require.NotNil(checkNodeInfo)

					if checkNodeInfo.ServerEncryptionPrivateKeyType == types.KEYTYPE_MLKEM1024 {
						require.NotNil(resp.MlkemCiphertext)
						require.Equal(types.KEYTYPE_MLKEM1024, resp.ServerEncryptionPublicKeyType)
					} else {
						require.NotNil(resp.ServerEncryptionPublicKeyBytes)
						require.Equal(types.KEYTYPE_X25519, resp.ServerEncryptionPublicKeyType)
					}

					// Now decrypt
					var receivedNodeCreds types.NodeCredentials
					require.NoError(nodeenrollment.DecryptMessage(ctx, resp.EncryptedNodeCredentials, checkNodeInfo, &receivedNodeCreds))
					if checkNodeInfo.ServerEncryptionPrivateKeyType == types.KEYTYPE_MLKEM1024 {
						assert.Equal(types.KEYTYPE_MLKEM1024, receivedNodeCreds.ServerEncryptionPublicKeyType)
					} else {
						assert.NotEmpty(receivedNodeCreds.ServerEncryptionPublicKeyBytes)
						assert.Equal(types.KEYTYPE_X25519, receivedNodeCreds.ServerEncryptionPublicKeyType)
					}
					assert.Len(receivedNodeCreds.CertificateBundles, 2)

					if tt.wantEncryptedChallenge {
						// The node-led flow should return an encrypted challenge that
						// decrypts to the node's original challenge.
						require.NotNil(receivedNodeCreds.EncryptedRegistrationChallenge)
						var decryptedChallenge types.RegistrationChallenge
						require.NoError(nodeenrollment.DecryptMessage(ctx, receivedNodeCreds.EncryptedRegistrationChallenge, checkNodeInfo, &decryptedChallenge))
						assert.Equal(nodeCreds.RegistrationChallenge.Challenge, decryptedChallenge.Challenge)
					}
				})
			}
		})
	}
}

// TestNodeLedRegistration_EndToEnd exercises the full node-led registration
// flow, including HandleFetchNodeCredentialsResponse, verifying that the
// challenge round-trip works correctly.
func TestNodeLedRegistration_EndToEnd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	nodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)

	// Authorization request carries the challenge so the server can store it.
	authzReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
	require.NoError(t, err)
	_, err = registration.AuthorizeNode(ctx, storage, authzReq)
	require.NoError(t, err)

	// Fetch request omits the challenge from the bundle.
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage, nodeenrollment.WithoutRegistrationChallenge(true))
	require.NoError(t, err)
	resp, err := registration.FetchNodeCredentials(ctx, storage, fetchReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.EncryptedNodeCredentials)

	// HandleFetchNodeCredentialsResponse decrypts the response and validates
	// the encrypted challenge against the locally stored one.
	updatedCreds, err := nodeCreds.HandleFetchNodeCredentialsResponse(ctx, storage, resp)
	require.NoError(t, err)
	require.NotNil(t, updatedCreds)
	assert.Len(t, updatedCreds.CertificateBundles, 2)
	// Challenge must be cleared after successful validation
	assert.Nil(t, updatedCreds.RegistrationChallenge)
}

// TestNodeLedRegistration_SubsequentFetch verifies that a second
// CreateFetchNodeCredentialsRequest succeeds after the node has already
// completed a full fetch/response cycle (i.e. after credentials are
// established).
//
// For MLKEM1024, the "already have ciphertext" branch in
// CreateFetchNodeCredentialsRequest must still populate reqInfo.MlkemParameters
// (with the ciphertext), otherwise it breaks without setting it and
// validateFetchRequestCommon rejects the request with "mlkem parameters are nil".
func TestNodeLedRegistration_SubsequentFetch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, kt := range nodetesting.TestKeyTypeVariants() {
		t.Run(kt.Name, func(t *testing.T) {
			t.Parallel()

			storage, err := inmem.New(ctx)
			require.NoError(t, err)

			_, err = rotation.RotateRootCertificates(ctx, storage)
			require.NoError(t, err)

			nodeCreds, err := types.NewNodeCredentials(ctx, storage, kt.Opts...)
			require.NoError(t, err)

			// --- First full registration cycle ---
			authzReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
			require.NoError(t, err)
			_, err = registration.AuthorizeNode(ctx, storage, authzReq)
			require.NoError(t, err)

			fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage, nodeenrollment.WithoutRegistrationChallenge(true))
			require.NoError(t, err)
			resp, err := registration.FetchNodeCredentials(ctx, storage, fetchReq)
			require.NoError(t, err)

			_, err = nodeCreds.HandleFetchNodeCredentialsResponse(ctx, storage, resp)
			require.NoError(t, err)

			if kt.KeyType == types.KEYTYPE_MLKEM1024 {
				require.NotEmpty(t, nodeCreds.MlkemParameters.SharedKey, "shared key must be set after first fetch")
				// Simulate the ciphertext-persist fix (separate bug): set it
				// manually here to isolate the reqInfo.MlkemParameters nil bug.
				nodeCreds.MlkemParameters.Ciphertext = resp.MlkemCiphertext
			}

			// HandleFetchNodeCredentialsResponse clears RegistrationChallenge and
			// RegistrationNonce.  Set a new challenge so CreateFetchNodeCredentialsRequest
			// can build a request (the renewal path needs some challenge/nonce).
			nodeCreds.RegistrationChallenge = &types.RegistrationChallenge{
				Challenge: make([]byte, nodeenrollment.NonceSize),
			}
			_, err = rand.Read(nodeCreds.RegistrationChallenge.Challenge)
			require.NoError(t, err)

			// --- Second fetch request ---
			// For MLKEM: CreateFetchNodeCredentialsRequest detects Ciphertext+SharedKey
			// are set and breaks without populating reqInfo.MlkemParameters.
			// validateFetchRequestCommon then rejects with "mlkem parameters are nil".
			fetchReq2, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
			require.NoError(t, err, "CreateFetchNodeCredentialsRequest must succeed on subsequent call")

			_, err = registration.FetchNodeCredentials(ctx, storage, fetchReq2)
			require.NoError(t, err, "FetchNodeCredentials must accept a subsequent fetch request")
		})
	}
}

// TestNodeLedRegistration_ChallengeMismatch verifies that if the server
// returns an encrypted challenge that does not match the node's stored value,
// HandleFetchNodeCredentialsResponse rejects it.
func TestNodeLedRegistration_ChallengeMismatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, kt := range nodetesting.TestKeyTypeVariants() {
		t.Run(kt.Name, func(t *testing.T) {
			t.Parallel()

			storage, err := inmem.New(ctx)
			require.NoError(t, err)

			_, err = rotation.RotateRootCertificates(ctx, storage)
			require.NoError(t, err)

			nodeCreds, err := types.NewNodeCredentials(ctx, storage, kt.Opts...)
			require.NoError(t, err)

			authzReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
			require.NoError(t, err)
			_, err = registration.AuthorizeNode(ctx, storage, authzReq)
			require.NoError(t, err)

			fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage, nodeenrollment.WithoutRegistrationChallenge(true))
			require.NoError(t, err)
			_, err = registration.FetchNodeCredentials(ctx, storage, fetchReq)
			require.NoError(t, err)

			// Load the stored nodeInfo so we can craft a malicious response using a
			// different server-side key pair (simulating a MITM).
			keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
			require.NoError(t, err)
			realNodeInfo := &types.NodeInformation{Id: keyId}
			require.NoError(t, storage.Load(ctx, realNodeInfo))

			var mitmResp *types.FetchNodeCredentialsResponse
			if kt.KeyType == types.KEYTYPE_MLKEM1024 {
				// MITM generates a new encapsulation from the node's decapsulation key.
				dk, err := mlkem.NewDecapsulationKey1024(nodeCreds.MlkemParameters.DecapsulationKey)
				require.NoError(t, err)
				mitmSharedKey, mitmCiphertext := dk.EncapsulationKey().Encapsulate()

				mitmNodeInfo := &types.NodeInformation{
					ServerEncryptionPrivateKeyType: types.KEYTYPE_MLKEM1024,
					MlkemParameters:                &types.MLKEMParameters{SharedKey: mitmSharedKey},
					CertificatePublicKeyPkix:       realNodeInfo.CertificatePublicKeyPkix,
				}
				wrongChallenge := &types.RegistrationChallenge{Challenge: []byte("this is not the right challenge")}
				encWrongChallenge, err := nodeenrollment.EncryptMessage(ctx, wrongChallenge, mitmNodeInfo)
				require.NoError(t, err)

				fakeCreds := &types.NodeCredentials{
					ServerEncryptionPublicKeyType:  types.KEYTYPE_MLKEM1024,
					EncryptedRegistrationChallenge: encWrongChallenge,
				}
				encFakeCreds, err := nodeenrollment.EncryptMessage(ctx, fakeCreds, mitmNodeInfo)
				require.NoError(t, err)

				mitmResp = &types.FetchNodeCredentialsResponse{
					ServerEncryptionPublicKeyType: types.KEYTYPE_MLKEM1024,
					MlkemCiphertext:               mitmCiphertext,
					EncryptedNodeCredentials:      encFakeCreds,
				}
			} else {
				// MITM generates its own ECDH key pair.
				mitmPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
				require.NoError(t, err)
				mitmPub := mitmPriv.PublicKey()

				// MITM encrypts a *wrong* challenge with the shared key it controls.
				mitmNodeInfo := &types.NodeInformation{
					ServerEncryptionPrivateKeyBytes: mitmPriv.Bytes(),
					ServerEncryptionPrivateKeyType:  types.KEYTYPE_X25519,
					EncryptionPublicKeyBytes:        realNodeInfo.EncryptionPublicKeyBytes,
					EncryptionPublicKeyType:         types.KEYTYPE_X25519,
					CertificatePublicKeyPkix:        realNodeInfo.CertificatePublicKeyPkix,
				}
				wrongChallenge := &types.RegistrationChallenge{Challenge: []byte("this is not the right challenge")}
				encWrongChallenge, err := nodeenrollment.EncryptMessage(ctx, wrongChallenge, mitmNodeInfo)
				require.NoError(t, err)

				// Build a forged NodeCredentials that contains the wrong encrypted challenge.
				fakeCreds := &types.NodeCredentials{
					ServerEncryptionPublicKeyBytes: mitmPub.Bytes(),
					ServerEncryptionPublicKeyType:  types.KEYTYPE_X25519,
					EncryptedRegistrationChallenge: encWrongChallenge,
				}
				encFakeCreds, err := nodeenrollment.EncryptMessage(ctx, fakeCreds, mitmNodeInfo)
				require.NoError(t, err)

				mitmResp = &types.FetchNodeCredentialsResponse{
					ServerEncryptionPublicKeyBytes: mitmPub.Bytes(),
					ServerEncryptionPublicKeyType:  types.KEYTYPE_X25519,
					EncryptedNodeCredentials:       encFakeCreds,
				}
			}

			_, err = nodeCreds.HandleFetchNodeCredentialsResponse(ctx, storage, mitmResp)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "challenge does not match")
		})
	}
}

// TestNodeLedRegistration_OldProtocolBackwardsCompat verifies that an
// old-style node-led request (nonce only, no RegistrationChallenge) is still
// accepted by a new server. This covers the upgrade window where workers
// haven't yet been updated.
func TestNodeLedRegistration_OldProtocolBackwardsCompat(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	// Simulate an old worker: create credentials but override with a plain nonce.
	nodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)

	// Build a request the old way: NonceSize nonce, no RegistrationChallenge.
	oldNonce := make([]byte, nodeenrollment.NonceSize)
	_, err = rand.Read(oldNonce)
	require.NoError(t, err)
	nodeCreds.RegistrationNonce = oldNonce
	nodeCreds.RegistrationChallenge = nil

	oldReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage, nodeenrollment.WithoutRegistrationChallenge(true))
	require.NoError(t, err)

	// Inject the nonce into the bundle manually (simulating old client code).
	var info types.FetchNodeCredentialsInfo
	require.NoError(t, proto.Unmarshal(oldReq.Bundle, &info))
	info.Nonce = oldNonce
	info.RegistrationChallenge = nil
	privKey, err := x509.ParsePKCS8PrivateKey(nodeCreds.CertificatePrivateKeyPkcs8)
	require.NoError(t, err)
	oldReq.Bundle, err = proto.Marshal(&info)
	require.NoError(t, err)
	oldReq.BundleSignature, err = privKey.(crypto.Signer).Sign(nil, oldReq.Bundle, crypto.Hash(0))
	require.NoError(t, err)

	// AuthorizeNode should accept the old-style nonce request.
	_, err = registration.AuthorizeNode(ctx, storage, oldReq)
	require.NoError(t, err)

	// FetchNodeCredentials should work too; no encrypted challenge returned
	// because RegistrationChallenge was not stored (old protocol path).
	resp, err := registration.FetchNodeCredentials(ctx, storage, oldReq)
	require.NoError(t, err)
	require.NotNil(t, resp)

	keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)
	storedInfo := &types.NodeInformation{Id: keyId}
	require.NoError(t, storage.Load(ctx, storedInfo))
	var receivedCreds types.NodeCredentials
	require.NoError(t, nodeenrollment.DecryptMessage(ctx, resp.EncryptedNodeCredentials, storedInfo, &receivedCreds))

	// Old protocol: nonce is echoed back; no encrypted challenge.
	assert.Equal(t, oldNonce, receivedCreds.RegistrationNonce)
	assert.Nil(t, receivedCreds.EncryptedRegistrationChallenge)
}

func TestNodeLedRegistration_OldPendingRegistrationAfterWorkerUpgrade(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	nodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)

	oldNonce := make([]byte, nodeenrollment.NonceSize)
	_, err = rand.Read(oldNonce)
	require.NoError(t, err)
	nodeCreds.RegistrationNonce = oldNonce
	nodeCreds.RegistrationChallenge = nil

	authzReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
	require.NoError(t, err)
	var info types.FetchNodeCredentialsInfo
	require.NoError(t, proto.Unmarshal(authzReq.Bundle, &info))
	require.Equal(t, oldNonce, info.Nonce)
	require.Nil(t, info.RegistrationChallenge)

	_, err = registration.AuthorizeNode(ctx, storage, authzReq)
	require.NoError(t, err)

	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage, nodeenrollment.WithoutRegistrationChallenge(true))
	require.NoError(t, err)
	resp, err := registration.FetchNodeCredentials(ctx, storage, fetchReq)
	require.NoError(t, err)

	updatedCreds, err := nodeCreds.HandleFetchNodeCredentialsResponse(ctx, storage, resp)
	require.NoError(t, err)
	assert.Len(t, updatedCreds.CertificateBundles, 2)
	assert.Nil(t, updatedCreds.RegistrationNonce)
	assert.Nil(t, updatedCreds.RegistrationChallenge)
}

func TestNodeLedRegistration_FetchNodeCredentials(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, kt := range nodetesting.TestKeyTypeVariants() {
		t.Run(kt.Name, func(t *testing.T) {
			t.Parallel()

			storage, err := inmem.New(ctx)
			require.NoError(t, err)

			_, err = rotation.RotateRootCertificates(ctx, storage)
			require.NoError(t, err)

			// This happens on the node
			nodeCreds, err := types.NewNodeCredentials(ctx, storage, kt.Opts...)
			require.NoError(t, err)
			// authzFetchReq carries the challenge for the server to store
			authzFetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
			require.NoError(t, err)
			// fetchReq omits the challenge from the bundle (new protocol)
			fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage, nodeenrollment.WithoutRegistrationChallenge(true))
			require.NoError(t, err)
			keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
			require.NoError(t, err)

			var encPublicKeyBytes []byte
			if kt.KeyType == types.KEYTYPE_X25519 {
				nodePrivKey, err := ecdh.X25519().NewPrivateKey(nodeCreds.EncryptionPrivateKeyBytes)
				require.NoError(t, err)
				encPublicKeyBytes = nodePrivKey.PublicKey().Bytes()
			}

			// If testing already authorized path, add this to storage
			baseNodeInfo := &types.NodeInformation{
				Id:                       keyId,
				CertificatePublicKeyPkix: nodeCreds.CertificatePublicKeyPkix,
				CertificatePublicKeyType: nodeCreds.CertificatePrivateKeyType,
				EncryptionPublicKeyBytes: encPublicKeyBytes,
				EncryptionPublicKeyType:  nodeCreds.EncryptionPrivateKeyType,
				RegistrationNonce:        nodeCreds.RegistrationNonce,
				RegistrationChallenge:    nodeCreds.RegistrationChallenge,
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

					if tt.nodeInfoSetupFn == nil {
						_ = storage.Remove(ctx, baseNodeInfo)
					}

					if tt.runAuthorization {
						_, err := registration.AuthorizeNode(ctx, storage, authzFetchReq)
						require.NoError(err)
					}

					resp, err := registration.FetchNodeCredentials(ctx, storage, fetchReq)
					require.NoError(err)
					require.NotNil(resp)

					checkNodeInfo := &types.NodeInformation{Id: baseNodeInfo.Id}
					require.NotNil(resp.EncryptedNodeCredentials)
					if kt.KeyType == types.KEYTYPE_MLKEM1024 {
						require.NotNil(resp.MlkemCiphertext)
						require.Equal(types.KEYTYPE_MLKEM1024, resp.ServerEncryptionPublicKeyType)
					} else {
						require.NotNil(resp.ServerEncryptionPublicKeyBytes)
						require.Equal(types.KEYTYPE_X25519, resp.ServerEncryptionPublicKeyType)
					}

					require.NoError(storage.Load(ctx, checkNodeInfo))
					require.NotNil(checkNodeInfo)
					var receivedNodeCreds types.NodeCredentials
					require.NoError(nodeenrollment.DecryptMessage(ctx, resp.EncryptedNodeCredentials, checkNodeInfo, &receivedNodeCreds))
					if kt.KeyType == types.KEYTYPE_MLKEM1024 {
						assert.Equal(types.KEYTYPE_MLKEM1024, receivedNodeCreds.ServerEncryptionPublicKeyType)
					} else {
						assert.NotEmpty(receivedNodeCreds.ServerEncryptionPublicKeyBytes)
						assert.Equal(types.KEYTYPE_X25519, receivedNodeCreds.ServerEncryptionPublicKeyType)
					}
					// New protocol: challenge is encrypted, not nonce
					assert.NotNil(receivedNodeCreds.EncryptedRegistrationChallenge)
					assert.Len(receivedNodeCreds.CertificateBundles, 2)

					// Verify the encrypted challenge decrypts to the original challenge
					var decryptedChallenge types.RegistrationChallenge
					require.NoError(nodeenrollment.DecryptMessage(ctx, receivedNodeCreds.EncryptedRegistrationChallenge, checkNodeInfo, &decryptedChallenge))
					assert.Equal(nodeCreds.RegistrationChallenge.Challenge, decryptedChallenge.Challenge)
				})
			}
		})
	}
}
