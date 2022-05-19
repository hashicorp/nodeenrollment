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

// FetchNodeCredentials fetches node credentials based on the submitted
// information; or, saves the request if it's the first time it's seen.
//
// A storage implementation can no-op the storage call for a NodeInformation
// that is not authorized if it doesn't want to persist unauthorized requests.
// This reduces attack surface from unauthorized requestors in storage but means
// being unable to list pending requests and their key IDs.
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

	switch {
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) nil storage", op)
	case req == nil:
		return nil, fmt.Errorf("(%s) nil request", op)
	case len(req.Bundle) == 0:
		return nil, fmt.Errorf("(%s) empty bundle", op)
	case len(req.BundleSignature) == 0:
		return nil, fmt.Errorf("(%s) empty bundle signature", op)
	}

	var reqInfo types.FetchNodeCredentialsInfo
	if err := proto.Unmarshal(req.Bundle, &reqInfo); err != nil {
		return nil, fmt.Errorf("(%s) cannot unmarshal request info: %w", op, err)
	}

	switch {
	case len(reqInfo.CertificatePublicKeyPkix) == 0:
		return nil, fmt.Errorf("(%s) empty node certificate public key", op)
	case reqInfo.CertificatePublicKeyType != types.KEYTYPE_KEYTYPE_ED25519:
		return nil, fmt.Errorf("(%s) unsupported node certificate public key type %v", op, reqInfo.CertificatePublicKeyType.String())
	case len(reqInfo.Nonce) == 0:
		return nil, fmt.Errorf("(%s) empty nonce", op)
	case len(reqInfo.EncryptionPublicKeyBytes) == 0:
		return nil, fmt.Errorf("(%s) empty node encryption public key", op)
	case reqInfo.EncryptionPublicKeyType != types.KEYTYPE_KEYTYPE_X25519:
		return nil, fmt.Errorf("(%s) unsupported node encryption public key type %v", op, reqInfo.EncryptionPublicKeyType.String())
	case len(reqInfo.Nonce) != nodeenrollment.NonceSize:
		return nil, fmt.Errorf("(%s) invalid registration nonce", op)
	}

	pubKey, err := x509.ParsePKIXPublicKey(reqInfo.CertificatePublicKeyPkix)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing public key: %w", op, err)
	}
	if !ed25519.Verify(pubKey.(ed25519.PublicKey), req.Bundle, req.BundleSignature) {
		return nil, fmt.Errorf("(%s) request bytes signature verification failed", op)
	}

	keyId, err := nodeenrollment.KeyIdFromPkix(reqInfo.CertificatePublicKeyPkix)
	if err != nil {
		return nil, fmt.Errorf("(%s) error deriving key id: %w", op, err)
	}

	var register bool
	nodeInfo, err := types.LoadNodeInformation(ctx, storage, keyId, opt...)
	if err != nil {
		if errors.Is(err, nodeenrollment.ErrNotFound) {
			register = true
		} else {
			return nil, fmt.Errorf("(%s) error fetching node registration request: %w", op, err)
		}
	}

	// If it's not found, it's the first request we've seen with this key ID, so
	// store it
	switch {
	case register:
		nodeInfo = &types.NodeInformation{
			Id:                       keyId,
			CertificatePublicKeyPkix: reqInfo.CertificatePublicKeyPkix,
			CertificatePublicKeyType: reqInfo.CertificatePublicKeyType,
			EncryptionPublicKeyBytes: reqInfo.EncryptionPublicKeyBytes,
			EncryptionPublicKeyType:  reqInfo.EncryptionPublicKeyType,
			RegistrationNonce:        reqInfo.Nonce,
			FirstSeen:                timestamppb.Now(),
		}
		if err := nodeInfo.Store(ctx, storage, opt...); err != nil {
			return nil, fmt.Errorf("(%s) error storing node registration request: %w", op, err)
		}
		return &types.FetchNodeCredentialsResponse{
			Authorized: false,
		}, nil

		// If we're here, we found the request already. See if it's authorized; if
		// not return. Otherwise skip this and return the node credentials below.
	case !nodeInfo.Authorized:
		return &types.FetchNodeCredentialsResponse{
			Authorized: false,
		}, nil

	default:
		// Verify the nonce matches, if so, move on and return the credentials
		if subtle.ConstantTimeCompare(nodeInfo.RegistrationNonce, reqInfo.Nonce) != 1 {
			return nil, fmt.Errorf("(%s) mismatched nonces between authorization and incoming fetch request", op)
		}
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

// AuthorizeNode authorizes a node that has sent a registration request
//
// Supported options: WithWrapper (passed through to LoadNodeInformation,
// LoadRootCertificates, and NodeInformation.Store)
func AuthorizeNode(
	ctx context.Context,
	storage nodeenrollment.Storage,
	keyId string,
	opt ...nodeenrollment.Option,
) error {
	const op = "nodeenrollment.registration.AuthorizeNode"
	switch {
	case nodeenrollment.IsNil(storage):
		return fmt.Errorf("(%s) nil storage", op)
	case keyId == "":
		return fmt.Errorf("(%s) empty key id", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	nodeInfo, err := types.LoadNodeInformation(ctx, storage, keyId, opt...)
	if err != nil {
		return fmt.Errorf("(%s) error loading node registration request: %w", op, err)
	}

	if nodeInfo.Authorized {
		return fmt.Errorf("(%s) node is already authorized", op)
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
		nodeInfo.ServerEncryptionPrivateKeyType = types.KEYTYPE_KEYTYPE_X25519
	}

	// Now save the authorized status back to the registration request
	nodeInfo.Authorized = true
	if err := nodeInfo.Store(ctx, storage, opt...); err != nil {
		return fmt.Errorf("(%s) error updating registration information: %w", op, err)
	}

	return nil
}
