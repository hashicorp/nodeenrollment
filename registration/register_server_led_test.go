// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package registration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/inmem"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestServerLedRegistration(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(err)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(err)

	// Ensure nil request and/or storage are caught
	_, token, err := registration.CreateServerLedActivationToken(ctx, nil, &types.ServerLedRegistrationRequest{})
	require.Error(err)
	assert.Contains(err.Error(), "nil storage")
	assert.Empty(token)
	_, token, err = registration.CreateServerLedActivationToken(ctx, storage, nil)
	require.Error(err)
	assert.Contains(err.Error(), "nil request")
	assert.Empty(token)

	wrapper := aead.TestWrapper(t)

	tokenId, token, err := registration.CreateServerLedActivationToken(ctx, storage, &types.ServerLedRegistrationRequest{}, nodeenrollment.WithStorageWrapper(wrapper))
	require.NoError(err)
	assert.NotEmpty(token)
	assert.True(strings.HasPrefix(token, nodeenrollment.ServerLedActivationTokenPrefix))

	nonce, err := base58.FastBase58Decoding(strings.TrimPrefix(token, nodeenrollment.ServerLedActivationTokenPrefix))
	require.NoError(err)

	// Decode the tokenNonce to verify new protocol fields are present.
	tokenNonce := new(types.ServerLedActivationTokenNonce)
	require.NoError(proto.Unmarshal(nonce, tokenNonce))

	// New protocol: activation token ID and server encryption public key must
	// be present in the nonce given to the node.
	assert.NotEmpty(tokenNonce.ActivationTokenId)
	assert.Equal(tokenId, tokenNonce.ActivationTokenId)
	assert.NotEmpty(tokenNonce.ServerEncryptionPublicKeyBytes)
	assert.Equal(types.KEYTYPE_X25519, tokenNonce.ServerEncryptionPublicKeyType)
	// Legacy fields must still be present for backwards compatibility.
	assert.NotEmpty(tokenNonce.Nonce)
	assert.NotEmpty(tokenNonce.HmacKeyBytes)

	hm := hmac.New(sha256.New, tokenNonce.HmacKeyBytes)
	hm.Write(tokenNonce.Nonce)
	idBytes := hm.Sum(nil)
	assert.Equal(tokenId, base58.FastBase58Encoding(idBytes))
	decodedTokenId, err := base58.FastBase58Decoding(tokenId)
	require.NoError(err)
	assert.Len(decodedTokenId, sha256.Size)

	tokenEntry, err := types.LoadServerLedActivationToken(ctx, storage, tokenId, nodeenrollment.WithStorageWrapper(wrapper))
	require.NoError(err)
	require.NotNil(tokenEntry)
	assert.NotEmpty(tokenEntry.Id)
	assert.NotNil(tokenEntry.CreationTime)
	assert.NotEmpty(tokenEntry.CreationTimeMarshaled)
	assert.Empty(tokenEntry.WrappingKeyId)
	// New protocol: server encryption private key and challenge must be stored.
	assert.NotEmpty(tokenEntry.ServerEncryptionPrivateKeyBytes)
	assert.Equal(types.KEYTYPE_X25519, tokenEntry.ServerEncryptionPrivateKeyType)
	assert.NotNil(tokenEntry.RegistrationChallenge)
	assert.NotEmpty(tokenEntry.RegistrationChallenge.Challenge)
	// The challenge stored on the server should equal the nonce sent to the node.
	assert.Equal(tokenNonce.Nonce, tokenEntry.RegistrationChallenge.Challenge)
}

// TestServerLedRegistration_EndToEnd exercises the full new-protocol
// server-led flow: token creation → node creates encrypted challenge →
// FetchNodeCredentials validates → HandleFetchNodeCredentialsResponse succeeds.
func TestServerLedRegistration_EndToEnd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	tokenId, activationToken, err := registration.CreateServerLedActivationToken(ctx, storage, &types.ServerLedRegistrationRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, tokenId)

	// Node side: create credentials and a fetch request using the activation token.
	nodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage,
		nodeenrollment.WithActivationToken(activationToken),
	)
	require.NoError(t, err)

	// Server side: FetchNodeCredentials validates the encrypted challenge and
	// authorizes the node.
	resp, err := registration.FetchNodeCredentials(ctx, storage, fetchReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.EncryptedNodeCredentials)

	// Node side: process the response. For server-led, HandleFetchNodeCredentialsResponse
	// does not re-check the challenge (the server already validated it).
	updatedCreds, err := nodeCreds.HandleFetchNodeCredentialsResponse(ctx, storage, resp,
		nodeenrollment.WithActivationToken(activationToken),
	)
	require.NoError(t, err)
	require.NotNil(t, updatedCreds)
	assert.Len(t, updatedCreds.CertificateBundles, 2)
	assert.Nil(t, updatedCreds.RegistrationChallenge)
}

func TestServerLedRegistration_ReloadedCredentialsRejectMismatchedServerKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	_, activationToken, err := registration.CreateServerLedActivationToken(ctx, storage, &types.ServerLedRegistrationRequest{})
	require.NoError(t, err)

	nodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)
	_, err = nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage,
		nodeenrollment.WithActivationToken(activationToken),
	)
	require.NoError(t, err)

	reloadedCreds, err := types.LoadNodeCredentials(ctx, storage, nodeenrollment.CurrentId)
	require.NoError(t, err)
	require.NotEmpty(t, reloadedCreds.ServerEncryptionPublicKeyBytes)

	_, err = reloadedCreds.HandleFetchNodeCredentialsResponse(ctx, storage, &types.FetchNodeCredentialsResponse{
		ServerEncryptionPublicKeyBytes: []byte("unexpected-server-key"),
		ServerEncryptionPublicKeyType:  types.KEYTYPE_X25519,
		EncryptedNodeCredentials:       []byte("not-empty"),
	}, nodeenrollment.WithActivationToken(activationToken))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server encryption public key in response does not match expected value")
}

// TestServerLedRegistration_BadChallenge verifies that FetchNodeCredentials
// rejects a request that carries a tampered EncryptedRegistrationChallenge.
func TestServerLedRegistration_BadChallenge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	_, activationToken, err := registration.CreateServerLedActivationToken(ctx, storage, &types.ServerLedRegistrationRequest{})
	require.NoError(t, err)

	nodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage,
		nodeenrollment.WithActivationToken(activationToken),
	)
	require.NoError(t, err)

	// Tamper with the EncryptedRegistrationChallenge inside the bundle.
	var info types.FetchNodeCredentialsInfo
	require.NoError(t, proto.Unmarshal(fetchReq.Bundle, &info))
	if len(info.EncryptedRegistrationChallenge) > 10 {
		info.EncryptedRegistrationChallenge[5] ^= 0xff
		info.EncryptedRegistrationChallenge[9] ^= 0xff
	} else {
		info.EncryptedRegistrationChallenge = []byte("notvalidencrypted")
	}
	fetchReq.Bundle, err = proto.Marshal(&info)
	require.NoError(t, err)
	// Re-sign with the node's key (simulating a local modification, not a
	// wire-level tamper, so the signature still validates).
	certPrivKeyRaw, err := x509.ParsePKCS8PrivateKey(nodeCreds.CertificatePrivateKeyPkcs8)
	require.NoError(t, err)
	certPrivKey := certPrivKeyRaw.(ed25519.PrivateKey)
	fetchReq.BundleSignature = ed25519.Sign(certPrivKey, fetchReq.Bundle)

	_, err = registration.FetchNodeCredentials(ctx, storage, fetchReq)
	require.Error(t, err)
	// Should fail during challenge decryption or validation.
	assert.True(t,
		strings.Contains(err.Error(), "decrypting registration challenge") ||
			strings.Contains(err.Error(), "invalid registration challenge"),
		"unexpected error: %v", err,
	)
}

// TestServerLedRegistration_TokenIdOnlyRejected verifies that observing the
// activation token ID is not enough to redeem a new-protocol server-led token.
func TestServerLedRegistration_TokenIdOnlyRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	tokenId, _, err := registration.CreateServerLedActivationToken(ctx, storage, &types.ServerLedRegistrationRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, tokenId)

	nodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
	require.NoError(t, err)

	tokenNonce, err := proto.Marshal(&types.ServerLedActivationTokenNonce{
		ActivationTokenId: tokenId,
	})
	require.NoError(t, err)

	var info types.FetchNodeCredentialsInfo
	require.NoError(t, proto.Unmarshal(fetchReq.Bundle, &info))
	info.Nonce = tokenNonce
	info.ActivationTokenId = ""
	info.EncryptedRegistrationChallenge = nil
	info.RegistrationChallenge = nil
	fetchReq.Bundle, err = proto.Marshal(&info)
	require.NoError(t, err)

	certPrivKeyRaw, err := x509.ParsePKCS8PrivateKey(nodeCreds.CertificatePrivateKeyPkcs8)
	require.NoError(t, err)
	certPrivKey := certPrivKeyRaw.(ed25519.PrivateKey)
	fetchReq.BundleSignature = ed25519.Sign(certPrivKey, fetchReq.Bundle)

	_, err = registration.FetchNodeCredentials(ctx, storage, fetchReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing legacy token nonce")
}

func TestServerLedRegistration_OldStoredTokenIdOnlyRejected(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	tokenNonce := &types.ServerLedActivationTokenNonce{
		Nonce:        []byte("legacy-token-nonce"),
		HmacKeyBytes: []byte("legacy-token-hmac-key"),
	}
	legacyTokenId := legacyServerLedTokenIdForTest(tokenNonce)
	require.NoError(t, (&types.ServerLedActivationToken{
		Id:           legacyTokenId,
		CreationTime: timestamppb.Now(),
	}).Store(ctx, storage))

	nodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
	require.NoError(t, err)
	idOnlyTokenNonce, err := proto.Marshal(&types.ServerLedActivationTokenNonce{
		ActivationTokenId: legacyTokenId,
	})
	require.NoError(t, err)

	var info types.FetchNodeCredentialsInfo
	require.NoError(t, proto.Unmarshal(fetchReq.Bundle, &info))
	info.Nonce = idOnlyTokenNonce
	info.ActivationTokenId = ""
	info.EncryptedRegistrationChallenge = nil
	info.RegistrationChallenge = nil
	fetchReq.Bundle, err = proto.Marshal(&info)
	require.NoError(t, err)

	certPrivKeyRaw, err := x509.ParsePKCS8PrivateKey(nodeCreds.CertificatePrivateKeyPkcs8)
	require.NoError(t, err)
	certPrivKey := certPrivKeyRaw.(ed25519.PrivateKey)
	fetchReq.BundleSignature = ed25519.Sign(certPrivKey, fetchReq.Bundle)

	_, err = registration.FetchNodeCredentials(ctx, storage, fetchReq)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing legacy token nonce")
}

func TestServerLedRegistration_OldStoredTokenBackwardsCompat(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	tokenNonce := &types.ServerLedActivationTokenNonce{
		Nonce:        []byte("legacy-token-nonce"),
		HmacKeyBytes: []byte("legacy-token-hmac-key"),
	}
	legacyTokenId := legacyServerLedTokenIdForTest(tokenNonce)
	require.NoError(t, (&types.ServerLedActivationToken{
		Id:           legacyTokenId,
		CreationTime: timestamppb.Now(),
	}).Store(ctx, storage))
	rawTokenNonce, err := proto.Marshal(tokenNonce)
	require.NoError(t, err)

	nodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
	require.NoError(t, err)

	var info types.FetchNodeCredentialsInfo
	require.NoError(t, proto.Unmarshal(fetchReq.Bundle, &info))
	info.Nonce = rawTokenNonce
	info.ActivationTokenId = ""
	info.EncryptedRegistrationChallenge = nil
	info.RegistrationChallenge = nil
	fetchReq.Bundle, err = proto.Marshal(&info)
	require.NoError(t, err)

	certPrivKeyRaw, err := x509.ParsePKCS8PrivateKey(nodeCreds.CertificatePrivateKeyPkcs8)
	require.NoError(t, err)
	certPrivKey := certPrivKeyRaw.(ed25519.PrivateKey)
	fetchReq.BundleSignature = ed25519.Sign(certPrivKey, fetchReq.Bundle)

	resp, err := registration.FetchNodeCredentials(ctx, storage, fetchReq)
	require.NoError(t, err)
	require.NotEmpty(t, resp.EncryptedNodeCredentials)
}

// TestServerLedRegistration_OldWorkerBackwardsCompat verifies that an
// old-style server-led request (Nonce = marshaled proto tokenNonce, no
// EncryptedRegistrationChallenge, no ActivationTokenId) is correctly routed
// to the server-led path and succeeds on a new server.
func TestServerLedRegistration_OldWorkerBackwardsCompat(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage, err := inmem.New(ctx)
	require.NoError(t, err)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	tokenId, activationToken, err := registration.CreateServerLedActivationToken(ctx, storage, &types.ServerLedRegistrationRequest{})
	require.NoError(t, err)
	assert.NotEmpty(t, tokenId)

	// Old worker: base58-decode the whole token and stuff it into Nonce, just
	// like old client code did (ignoring new fields it doesn't know about).
	rawNonce, err := base58.FastBase58Decoding(strings.TrimPrefix(activationToken, nodeenrollment.ServerLedActivationTokenPrefix))
	require.NoError(t, err)

	nodeCreds, err := types.NewNodeCredentials(ctx, storage)
	require.NoError(t, err)

	// Build a new-style request but override it to look like an old one.
	fetchReq, err := nodeCreds.CreateFetchNodeCredentialsRequest(ctx, storage)
	require.NoError(t, err)
	var info types.FetchNodeCredentialsInfo
	require.NoError(t, proto.Unmarshal(fetchReq.Bundle, &info))
	// Old worker puts raw bytes in Nonce, not in ActivationTokenId/EncryptedRegistrationChallenge.
	info.Nonce = rawNonce
	info.ActivationTokenId = ""
	info.EncryptedRegistrationChallenge = nil
	info.RegistrationChallenge = nil
	fetchReq.Bundle, err = proto.Marshal(&info)
	require.NoError(t, err)
	certPrivKeyRaw2, err := x509.ParsePKCS8PrivateKey(nodeCreds.CertificatePrivateKeyPkcs8)
	require.NoError(t, err)
	certPrivKey2 := certPrivKeyRaw2.(ed25519.PrivateKey)
	fetchReq.BundleSignature = ed25519.Sign(certPrivKey2, fetchReq.Bundle)

	// FetchNodeCredentials must route this to the server-led path (not node-led)
	// and succeed via the legacy nonce/HMAC fallback.
	resp, err := registration.FetchNodeCredentials(ctx, storage, fetchReq)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotEmpty(t, resp.EncryptedNodeCredentials)

	// Load the stored node info and decrypt the response to confirm success.
	keyId, err := nodeenrollment.KeyIdFromPkix(nodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)
	storedInfo := &types.NodeInformation{Id: keyId}
	require.NoError(t, storage.Load(ctx, storedInfo))
	var receivedCreds types.NodeCredentials
	require.NoError(t, nodeenrollment.DecryptMessage(ctx, resp.EncryptedNodeCredentials, storedInfo, &receivedCreds))
	assert.Len(t, receivedCreds.CertificateBundles, 2)
}

func legacyServerLedTokenIdForTest(tokenNonce *types.ServerLedActivationTokenNonce) string {
	hm := hmac.New(sha256.New, tokenNonce.HmacKeyBytes)
	return base58.FastBase58Encoding(hm.Sum(tokenNonce.Nonce))
}
