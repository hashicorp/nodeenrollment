// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package registration

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
)

// validateFetchRequestCommon is common logic between FetchNodeCredentials and
// AuthorizeNode to validate the incoming request.
//
// NOTE: Users of the function should check the error to see if it is
// nodeenrollment.ErrNotFound and customize logic appropriately. It is possible
// for this function to return request info and also ErrNotFound to enable this.
//
// Supported options: WithWrapper (passed through to LoadNodeInformation),
// WithNotBeforeClockSkew/WithNotAfterClockSkew, WithState (passed through to
// authorizeNodeCommon.
func validateFetchRequestCommon(
	ctx context.Context,
	storage nodeenrollment.Storage,
	req *types.FetchNodeCredentialsRequest,
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

	return reqInfo, nil, nodeenrollment.ErrNotFound
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

	reqInfo, nodeInfo, err := validateFetchRequestCommon(ctx, storage, req, opt...)
	switch {
	case err == nil && nodeInfo == nil:
		// Unauthorized, so return empty
		return new(types.FetchNodeCredentialsResponse), nil

	case err == nil:
		// All is good, continue after this switch

	case !errors.Is(err, nodeenrollment.ErrNotFound):
		return nil, fmt.Errorf("(%s) error looking up node information from storage: %w", op, err)

	case errors.Is(err, nodeenrollment.ErrNotFound) && len(reqInfo.Nonce) != 0:
		// We expect to get this error if the node doesn't exist yet due to
		// having a server-led activation token included, so check for that and
		// authorize it
		tokenNonce := new(types.ServerLedActivationTokenNonce)
		if err := proto.Unmarshal(reqInfo.Nonce, tokenNonce); err != nil {
			if strings.Contains(err.Error(), "cannot parse invalid wire-format data") {
				return nil, fmt.Errorf("(%s) invalid registration nonce: %w", op, err)
			}
			return nil, fmt.Errorf("(%s) error unmarshaling server-led activation token: %w", op, err)
		}
		switch {
		case len(tokenNonce.Nonce) == 0:
			return nil, fmt.Errorf("(%s) nil server-led activation token nonce", op)
		case len(tokenNonce.HmacKeyBytes) == 0:
			return nil, fmt.Errorf("(%s) nil server-led activation token hmac key bytes", op)
		}
		nodeInfo, err = validateServerLedActivationToken(ctx, storage, reqInfo, tokenNonce, opt...)
		if err != nil {
			return nil, fmt.Errorf("(%s) error validating server-led activation token: %w", op, err)
		}
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
