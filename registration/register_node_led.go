package registration

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	mathrand "math/rand"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
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
// Supported options: WithWrapper (passed through to LoadNodeInformation)
func validateFetchRequest(
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

	var reqInfo types.FetchNodeCredentialsInfo
	if err := proto.Unmarshal(req.Bundle, &reqInfo); err != nil {
		return nil, nil, fmt.Errorf("(%s) cannot unmarshal request info: %w", op, err)
	}

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
	case len(reqInfo.Nonce) != nodeenrollment.NonceSize:
		return nil, nil, fmt.Errorf("(%s) invalid registration nonce", op)
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

	nodeInfo, err := types.LoadNodeInformation(ctx, storage, keyId, opt...)

	return &reqInfo, nodeInfo, err
}

// FetchNodeCredentials fetches node credentials based on the submitted
// information
//
// Supported options: WithRandomReader, WithWrapper (passed through to
// LoadNoadInformation, NodeInformation.Store, and LoadRootCeritificates)
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

	reqInfo, nodeInfo, err := validateFetchRequest(ctx, storage, req, opt...)
	if err != nil && !errors.Is(err, nodeenrollment.ErrNotFound) {
		return nil, fmt.Errorf("(%s) error looking up node information from storage: %w", op, err)
	}

	if nodeInfo == nil {
		return &types.FetchNodeCredentialsResponse{
			Authorized: false,
		}, nil
	}

	keyId, err := nodeenrollment.KeyIdFromPkix(reqInfo.CertificatePublicKeyPkix)
	if err != nil {
		return nil, fmt.Errorf("(%s) error deriving key id: %w", op, err)
	}

	// Runs some validations
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
		keyId,
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
		Authorized:                        true,
	}, nil
}

// AuthorizeNode authorizes a node via a registration request
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
// stored NodeInformation)
func AuthorizeNode(
	ctx context.Context,
	storage nodeenrollment.Storage,
	req *types.FetchNodeCredentialsRequest,
	opt ...nodeenrollment.Option,
) error {
	const op = "nodeenrollment.registration.AuthorizeNode"

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	reqInfo, nodeInfo, err := validateFetchRequest(ctx, storage, req, opt...)
	if err != nil && !errors.Is(err, nodeenrollment.ErrNotFound) {
		return fmt.Errorf("(%s) error looking up node information from storage: %w", op, err)
	}

	if nodeInfo != nil {
		return fmt.Errorf("(%s) authorize node cannot be called on an existing node", op)
	}

	keyId, err := nodeenrollment.KeyIdFromPkix(reqInfo.CertificatePublicKeyPkix)
	if err != nil {
		return fmt.Errorf("(%s) error deriving key id: %w", op, err)
	}

	nodeInfo = &types.NodeInformation{
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
		return fmt.Errorf("(%s) error parsing node certificate public key: %w", op, err)
	}
	certPubKey, ok := certPubKeyRaw.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("(%s) unable to interpret node certificate public key as an ed25519 public key", op)
	}

	rootCerts, err := types.LoadRootCertificates(ctx, storage, opt...)
	if err != nil {
		return fmt.Errorf("(%s) error fetching current root certificates: %w", op, err)
	}

	// Create certificates
	{
		for _, rootCert := range []*types.RootCertificate{rootCerts.Current, rootCerts.Next} {
			caCert, caPrivKey, err := rootCert.SigningParams(ctx)
			if err != nil {
				return fmt.Errorf("(%s) error parsing signing parameters from root: %w", op, err)
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
				return fmt.Errorf("(%s) error creating certificate: %w", op, err)
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
			return fmt.Errorf("(%s) error reading random bytes to generate server encryption key: %w", op, err)
		case n != curve25519.ScalarSize:
			return fmt.Errorf("(%s) wrong number of random bytes read when generating server encryption key, expected %d but got %d", op, curve25519.ScalarSize, n)
		}
		nodeInfo.ServerEncryptionPrivateKeyType = types.KEYTYPE_X25519
	}

	// Save the node information into storage
	if err := nodeInfo.Store(ctx, storage, opt...); err != nil {
		return fmt.Errorf("(%s) error updating registration information: %w", op, err)
	}

	return nil
}
