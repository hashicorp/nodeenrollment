// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package registration

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"strings"
	"time"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

// validateFetchRequest is common logic between FetchNodeCredentials and
// AuthorizeNode to validate the incoming request.
//
// NOTE: Users of the function should check the error to see if it is
// nodeenrollment.ErrNotFound and customize logic appropriately
//
// Supported options: WithWrapper (passed through to LoadNodeInformation),
// WithNotBeforeClockSkew/WithNotAfterClockSkew, WithState (passed through to
// authorizeNodeCommon.
func validateFetchRequest(
	ctx context.Context,
	storage nodeenrollment.Storage,
	req *types.FetchNodeCredentialsRequest,
	fromAuthorize bool,
	opt ...nodeenrollment.Option,
) (*types.FetchNodeCredentialsInfo, *types.NodeInformation, error) {
	const op = "nodeenrollment.registration.validateFetchRequest"

	switch {
	case nodeenrollment.IsNil(storage):
		return nil, nil, fmt.Errorf("(%s) nil storage", op)
	case req == nil:
		return nil, nil, fmt.Errorf("(%s) nil request", op)
	case len(req.Bundle) == 0:
		return nil, nil, fmt.Errorf("(%s) empty bundle", op)
	case len(req.BundleSignature) == 0:
		return nil, nil, fmt.Errorf("(%s) empty bundle signature", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	reqInfo := new(types.FetchNodeCredentialsInfo)
	if err := proto.Unmarshal(req.Bundle, reqInfo); err != nil {
		return nil, nil, fmt.Errorf("(%s) cannot unmarshal request info: %w", op, err)
	}

	now := time.Now()
	switch {
	case len(reqInfo.CertificatePublicKeyPkix) == 0:
		return nil, nil, fmt.Errorf("(%s) empty node certificate public key", op)
	case reqInfo.CertificatePublicKeyType != types.KEYTYPE_ED25519:
		return nil, nil, fmt.Errorf("(%s) unsupported node certificate public key type %v", op, reqInfo.CertificatePublicKeyType.String())
	case len(reqInfo.Nonce) == 0:
		return nil, nil, fmt.Errorf("(%s) empty nonce", op)
	case len(reqInfo.EncryptionPublicKeyBytes) == 0:
		return nil, nil, fmt.Errorf("(%s) empty node encryption public key", op)
	case reqInfo.EncryptionPublicKeyType != types.KEYTYPE_X25519:
		return nil, nil, fmt.Errorf("(%s) unsupported node encryption public key type %v", op, reqInfo.EncryptionPublicKeyType.String())
	case reqInfo.NotBefore.AsTime().Add(opts.WithNotBeforeClockSkew).After(now):
		return nil, nil, fmt.Errorf("(%s) validity period is after current time", op)
	case reqInfo.NotAfter.AsTime().Add(opts.WithNotAfterClockSkew).Before(now):
		return nil, nil, fmt.Errorf("(%s) validity period is before current time", op)
	}

	pubKeyRaw, err := x509.ParsePKIXPublicKey(reqInfo.CertificatePublicKeyPkix)
	if err != nil {
		return nil, nil, fmt.Errorf("(%s) error parsing public key: %w", op, err)
	}
	pubKey, ok := pubKeyRaw.(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("(%s) error considering public key as ed25519: %w", op, err)
	}
	if !ed25519.Verify(pubKey, req.Bundle, req.BundleSignature) {
		return nil, nil, fmt.Errorf("(%s) request bytes signature verification failed", op)
	}

	keyId, err := nodeenrollment.KeyIdFromPkix(reqInfo.CertificatePublicKeyPkix)
	if err != nil {
		return nil, nil, fmt.Errorf("(%s) error deriving key id: %w", op, err)
	}

	// If it's our expected nonce-size it's a normal fetch, not a
	// server-generated activation token
	if len(reqInfo.Nonce) == nodeenrollment.NonceSize {
		nodeInfo, err := types.LoadNodeInformation(ctx, storage, keyId, opt...)
		return reqInfo, nodeInfo, err
	}

	// Treat it as a server-led activation token; first ensure this path didn't
	// come an authorize call
	if fromAuthorize {
		return nil, nil, fmt.Errorf("(%s) server-led activation tokens cannot be used with node-led authorize call", op)
	}

	tokenNonce := new(types.ServerLedActivationTokenNonce)
	if err := proto.Unmarshal(reqInfo.Nonce, tokenNonce); err != nil {
		if strings.Contains(err.Error(), "cannot parse invalid wire-format data") {
			return nil, nil, fmt.Errorf("(%s) invalid registration nonce: %w", op, err)
		}
		return nil, nil, fmt.Errorf("(%s) error unmarshaling server-led activation token: %w", op, err)
	}
	switch {
	case len(tokenNonce.Nonce) == 0:
		return nil, nil, fmt.Errorf("(%s) nil activation token nonce", op)
	case len(tokenNonce.HmacKeyBytes) == 0:
		return nil, nil, fmt.Errorf("(%s) nil activation token hmac key bytes", op)
	}

	// Generate the ID from the token values for lookup
	hm := hmac.New(sha256.New, tokenNonce.HmacKeyBytes)
	idBytes := hm.Sum(tokenNonce.Nonce)
	tokenEntry, err := types.LoadServerLedActivationToken(ctx, storage, base58.FastBase58Encoding(idBytes), opt...)
	if err != nil {
		return nil, nil, fmt.Errorf("(%s) error looking up activation token: %w", op, err)
	}
	if tokenEntry == nil {
		// Returning ErrNotFound here will result in the Fetch call returning unauthorized
		return nil, nil, fmt.Errorf("(%s) activation token from lookup is nil: %w", op, nodeenrollment.ErrNotFound)
	}

	// Validate the time since creation
	switch {
	case tokenEntry.CreationTime == nil:
		return nil, nil, fmt.Errorf("(%s) nil activation token creation time", op)
	case tokenEntry.CreationTime.AsTime().IsZero():
		return nil, nil, fmt.Errorf("(%s) activation token creation time is zero", op)
	}
	if tokenEntry.CreationTime.AsTime().Add(opts.WithMaximumServerLedActivationTokenLifetime).Before(time.Now()) {
		return nil, nil, fmt.Errorf("(%s) activation token has expired", op)
	}

	// If state was provided, use it. Note that it may clash if state is passed
	// into the function directly; either transfer state via token entry, or
	// when calling this function.
	if tokenEntry.State != nil {
		opt = append(opt, nodeenrollment.WithState(tokenEntry.State))
	}

	// We need to remove this since it's one-time-use. Note that it's up to the
	// storage implementation to have this be truly one-time or not (e.g. in a
	// transaction). If possible, storage should communicate anything unexpected
	// (such as the value not being found) as an error so we don't proceed
	// towards authorization.
	if err := storage.Remove(ctx, tokenEntry); err != nil {
		return nil, nil, fmt.Errorf("(%s) error removing server-led activation token: %w", op, err)
	}

	// Verify that we don't have an authorization already for the given key ID
	if keyCheck, _ := types.LoadNodeInformation(ctx, storage, keyId, opt...); keyCheck != nil {
		return nil, nil, fmt.Errorf("(%s) node cannot be authorized as there is an existing node", op)
	}

	// Authorize the node; we'll then fall through to the rest of the fetch
	// workflow (we've already ensured we're not in an authorize call up
	// above)
	nodeInfo, err := authorizeNodeCommon(ctx, storage, reqInfo, opt...)
	return reqInfo, nodeInfo, err
}

// FetchNodeCredentials fetches node credentials based on the submitted
// information.
//
// Supported options: WithRandomReader, WithWrapper (passed through to
// LoadNodeInformation, NodeInformation.Store, and LoadRootCertificates),
// WithNotBeforeClockSkew/WithNotAfterClockSkew/WithState (passed through to
// validateFetchRequest)
//
// Note: If the request nonce is a server-led activation token and it contains
// state, this will overwrite any state passed in via options to this function;
// either transfer state via the activation token, or when calling this
// function.
func FetchNodeCredentials(
	ctx context.Context,
	storage nodeenrollment.Storage,
	req *types.FetchNodeCredentialsRequest,
	opt ...nodeenrollment.Option,
) (*types.FetchNodeCredentialsResponse, error) {
	const op = "nodeenrollment.registration.FetchNodeCredentials"

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	reqInfo, nodeInfo, err := validateFetchRequest(ctx, storage, req, false, opt...)
	if err != nil && !errors.Is(err, nodeenrollment.ErrNotFound) {
		return nil, fmt.Errorf("(%s) error looking up node information from storage: %w", op, err)
	}

	if nodeInfo == nil {
		// Unauthorized, so return empty
		return new(types.FetchNodeCredentialsResponse), nil
	}

	// Run some validations
	if subtle.ConstantTimeCompare(nodeInfo.RegistrationNonce, reqInfo.Nonce) != 1 {
		return nil, fmt.Errorf("(%s) mismatched nonces between authorization and incoming fetch request", op)
	}

	if subtle.ConstantTimeCompare(nodeInfo.CertificatePublicKeyPkix, reqInfo.CertificatePublicKeyPkix) != 1 {
		return nil, fmt.Errorf("(%s) mismatched certificate public keys between authorization and incoming fetch request", op)
	}

	if subtle.ConstantTimeCompare(nodeInfo.EncryptionPublicKeyBytes, reqInfo.EncryptionPublicKeyBytes) != 1 {
		return nil, fmt.Errorf("(%s) mismatched encryption public keys between authorization and incoming fetch request", op)
	}

	serverEncryptionPublicKey, err := curve25519.X25519(nodeInfo.ServerEncryptionPrivateKeyBytes, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("(%s) error deriving server public encryption key: %w", op, err)
	}

	nodeCreds := &types.NodeCredentials{
		ServerEncryptionPublicKeyBytes: serverEncryptionPublicKey,
		ServerEncryptionPublicKeyType:  nodeInfo.ServerEncryptionPrivateKeyType,
		RegistrationNonce:              nodeInfo.RegistrationNonce,
		CertificateBundles:             nodeInfo.CertificateBundles,
	}

	encryptedBytes, err := nodeenrollment.EncryptMessage(
		ctx,
		nodeCreds,
		nodeInfo,
		opt...,
	)
	if err != nil {
		return nil, fmt.Errorf("(%s) error encrypting message: %w", op, err)
	}

	rootCerts, err := types.LoadRootCertificates(ctx, storage, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error fetching current root certificates: %w", op, err)
	}

	_, signer, err := rootCerts.Current.SigningParams(ctx)
	if err != nil {
		return nil, fmt.Errorf("(%s) error getting signing params: %w", op, err)
	}

	sigBytes, err := signer.Sign(opts.WithRandomReader, encryptedBytes, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("(%s) error signing request data message: %w", op, err)
	}

	return &types.FetchNodeCredentialsResponse{
		EncryptedNodeCredentials:          encryptedBytes,
		EncryptedNodeCredentialsSignature: sigBytes,
		ServerEncryptionPublicKeyBytes:    serverEncryptionPublicKey,
		ServerEncryptionPublicKeyType:     nodeInfo.ServerEncryptionPrivateKeyType,
	}, nil
}

// AuthorizeNode authorizes a node via a registration request.
//
// Note: THIS IS NOT A CONCURRENCY SAFE FUNCTION. In most cases, the given
// storage should ensure concurrency safety; as examples, version numbers could
// be used within NodeInformation's "state" parameter, or the application using
// this library could implement a higher-level lock on the API that leads to
// calling this function. Failing to account for concurrency could mean that two
// calls to AuthorizeNode running concurrently result in different
// certificate/encryption parameters being saved on the server vs. sent to the
// node.
//
// Supported options: WithWrapper (passed through to LoadNodeInformation,
// LoadRootCertificates, and NodeInformation.Store), WithState (set into the
// stored NodeInformation), WithNotBeforeClockSkew/WithNotAfterClockSkew (passed
// through to validateFetchRequest), WithSkipStorage, WithRandomReader
func AuthorizeNode(
	ctx context.Context,
	storage nodeenrollment.Storage,
	req *types.FetchNodeCredentialsRequest,
	opt ...nodeenrollment.Option,
) (*types.NodeInformation, error) {
	const op = "nodeenrollment.registration.AuthorizeNode"

	reqInfo, nodeInfo, err := validateFetchRequest(ctx, storage, req, true, opt...)
	if err != nil && !errors.Is(err, nodeenrollment.ErrNotFound) {
		return nil, fmt.Errorf("(%s) error looking up node information from storage: %w", op, err)
	}

	if nodeInfo != nil {
		return nil, fmt.Errorf("(%s) authorize node cannot be called on an existing node", op)
	}

	return authorizeNodeCommon(ctx, storage, reqInfo, opt...)
}

// Note: this is called via paths that run the common validateFetchRequest
// function which contains common validation functions
func authorizeNodeCommon(
	ctx context.Context,
	storage nodeenrollment.Storage,
	reqInfo *types.FetchNodeCredentialsInfo,
	opt ...nodeenrollment.Option,
) (*types.NodeInformation, error) {
	const op = "nodeenrollment.registration.authorizeNodeCommon"
	keyId, err := nodeenrollment.KeyIdFromPkix(reqInfo.CertificatePublicKeyPkix)
	if err != nil {
		return nil, fmt.Errorf("(%s) error deriving key id: %w", op, err)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	nodeInfo := &types.NodeInformation{
		Id:                       keyId,
		CertificatePublicKeyPkix: reqInfo.CertificatePublicKeyPkix,
		CertificatePublicKeyType: reqInfo.CertificatePublicKeyType,
		EncryptionPublicKeyBytes: reqInfo.EncryptionPublicKeyBytes,
		EncryptionPublicKeyType:  reqInfo.EncryptionPublicKeyType,
		RegistrationNonce:        reqInfo.Nonce,
		State:                    opts.WithState,
	}

	certPubKeyRaw, err := x509.ParsePKIXPublicKey(nodeInfo.CertificatePublicKeyPkix)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing node certificate public key: %w", op, err)
	}
	certPubKey, ok := certPubKeyRaw.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("(%s) unable to interpret node certificate public key as an ed25519 public key", op)
	}

	rootCerts, err := types.LoadRootCertificates(ctx, storage, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error fetching current root certificates: %w", op, err)
	}

	// Create certificates
	{
		for _, rootCert := range []*types.RootCertificate{rootCerts.Current, rootCerts.Next} {
			caCert, caPrivKey, err := rootCert.SigningParams(ctx)
			if err != nil {
				return nil, fmt.Errorf("(%s) error parsing signing parameters from root: %w", op, err)
			}

			template := &x509.Certificate{
				AuthorityKeyId: caCert.SubjectKeyId,
				SubjectKeyId:   nodeInfo.CertificatePublicKeyPkix,
				ExtKeyUsage: []x509.ExtKeyUsage{
					x509.ExtKeyUsageClientAuth,
				},
				Subject: pkix.Name{
					CommonName: nodeInfo.Id,
				},
				DNSNames:     []string{nodeenrollment.CommonDnsName},
				KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
				SerialNumber: big.NewInt(mathrand.Int63()),
				NotBefore:    caCert.NotBefore,
				NotAfter:     caCert.NotAfter,
			}

			certificateDer, err := x509.CreateCertificate(opts.WithRandomReader, template, caCert, ed25519.PublicKey(certPubKey), caPrivKey)
			if err != nil {
				return nil, fmt.Errorf("(%s) error creating certificate: %w", op, err)
			}

			nodeInfo.CertificateBundles = append(nodeInfo.CertificateBundles, &types.CertificateBundle{
				CertificateDer:       certificateDer,
				CaCertificateDer:     rootCert.CertificateDer,
				CertificateNotBefore: timestamppb.New(template.NotBefore),
				CertificateNotAfter:  timestamppb.New(template.NotAfter),
			})
		}
	}

	// Create server encryption keys
	{
		nodeInfo.ServerEncryptionPrivateKeyBytes = make([]byte, curve25519.ScalarSize)
		n, err := opts.WithRandomReader.Read(nodeInfo.ServerEncryptionPrivateKeyBytes)
		switch {
		case err != nil:
			return nil, fmt.Errorf("(%s) error reading random bytes to generate server encryption key: %w", op, err)
		case n != curve25519.ScalarSize:
			return nil, fmt.Errorf("(%s) wrong number of random bytes read when generating server encryption key, expected %d but got %d", op, curve25519.ScalarSize, n)
		}
		nodeInfo.ServerEncryptionPrivateKeyType = types.KEYTYPE_X25519
	}

	// Save the node information into storage if not skipped
	if !opts.WithSkipStorage {
		if err := nodeInfo.Store(ctx, storage, opt...); err != nil {
			return nil, fmt.Errorf("(%s) error updating registration information: %w", op, err)
		}
	}

	return nodeInfo, nil
}
