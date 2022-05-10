package noderegistration

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

	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/nodetypes"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

// FetchNodeCredentials fetches node credentials based on the submitted
// information; or, saves the request if it's the first time it's seen
//
// Supported options: WithRandomReader, WithWrapper (passed through to
// NodeInformation.Load), WithSkipStorage
func FetchNodeCredentials(
	ctx context.Context,
	storage nodee.Storage,
	req *nodetypes.FetchNodeCredentialsRequest,
	opt ...nodee.Option,
) (*nodetypes.FetchNodeCredentialsResponse, error) {
	const op = "nodee.noderegistration.FetchNodeCredentials"

	opts, err := nodee.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	// log.Println(op)
	switch {
	case storage == nil:
		return nil, fmt.Errorf("(%s) nil storage passed in", op)
	case req == nil:
		return nil, fmt.Errorf("(%s) nil request passed in", op)
	case len(req.Bundle) == 0:
		return nil, fmt.Errorf("(%s) empty bundle passed in", op)
	case len(req.BundleSignature) == 0:
		return nil, fmt.Errorf("(%s) empty bundle signature passed in", op)
	}

	var reqInfo nodetypes.FetchNodeCredentialsInfo
	if err := proto.Unmarshal(req.Bundle, &reqInfo); err != nil {
		return nil, fmt.Errorf("(%s) cannot unmarshal request info: %w", op, err)
	}

	switch {
	case len(reqInfo.CertificatePublicKeyPkix) == 0:
		return nil, fmt.Errorf("(%s) empty node certificate public key passed in", op)
	case reqInfo.CertificatePublicKeyType != nodetypes.KEYTYPE_KEYTYPE_ED25519:
		return nil, fmt.Errorf("(%s) unsupported node certificate public key type %v", op, reqInfo.CertificatePublicKeyType.String())
	case len(reqInfo.Nonce) == 0:
		return nil, fmt.Errorf("(%s) empty nonce passed in", op)
	}

	// log.Println(op, "parsing public key")
	pubKey, err := x509.ParsePKIXPublicKey(reqInfo.CertificatePublicKeyPkix)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing public key: %w", op, err)
	}
	if !ed25519.Verify(pubKey.(ed25519.PublicKey), req.Bundle, req.BundleSignature) {
		// log.Println(op, "failed to verify")
		return nil, fmt.Errorf("(%s) request bytes signature verification failed", op)
	}

	keyId := nodee.KeyIdFromPkix(reqInfo.CertificatePublicKeyPkix)
	// log.Println("fetch node creds with keyId", keyId)

	var register bool
	nodeInfo, err := nodetypes.LoadNodeInformation(ctx, storage, keyId, opt...)
	if err != nil {
		if errors.Is(err, nodee.ErrNotFound) {
			register = true
		} else {
			return nil, fmt.Errorf("(%s) error fetching node registration request: %w", op, err)
		}
	}

	// If it's not found, it's the first request we've seen with this key ID, so
	// store it
	switch {
	case register:
		switch {
		case len(reqInfo.EncryptionPublicKeyBytes) == 0:
			return nil, fmt.Errorf("(%s) empty node encryption public key passed in", op)
		case reqInfo.EncryptionPublicKeyType != nodetypes.KEYTYPE_KEYTYPE_X25519:
			return nil, fmt.Errorf("(%s) unsupported node encryption public key type %v", op, reqInfo.EncryptionPublicKeyType.String())
		case len(reqInfo.Nonce) != nodee.NonceSize:
			return nil, fmt.Errorf("(%s) invalid registration nonce passed in", op)
		}

		nodeInfo = &nodetypes.NodeInformation{
			Id:                       keyId,
			CertificatePublicKeyPkix: reqInfo.CertificatePublicKeyPkix,
			CertificatePublicKeyType: reqInfo.CertificatePublicKeyType,
			EncryptionPublicKeyBytes: reqInfo.EncryptionPublicKeyBytes,
			EncryptionPublicKeyType:  reqInfo.EncryptionPublicKeyType,
			RegistrationNonce:        reqInfo.Nonce,
			FirstSeen:                timestamppb.Now(),
		}
		// log.Println("storing node info with key", nodeInfo.Id)
		if err := nodeInfo.Store(ctx, storage, opt...); err != nil {
			return nil, fmt.Errorf("(%s) error storing node registration request: %w", op, err)
		}
		return &nodetypes.FetchNodeCredentialsResponse{
			Authorized: false,
		}, nil

		// If we're here, we found the request already. See if it's authorized; if
		// not return. Otherwise skip this and return the node credentials below.
	case !nodeInfo.Authorized:
		return &nodetypes.FetchNodeCredentialsResponse{
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

	nodeCreds := &nodetypes.NodeCredentials{
		ServerEncryptionPublicKeyBytes: serverEncryptionPublicKey,
		ServerEncryptionPublicKeyType:  nodeInfo.ServerEncryptionPrivateKeyType,
		RegistrationNonce:              nodeInfo.RegistrationNonce,
		CertificateBundles:             nodeInfo.CertificateBundles,
	}

	encryptedBytes, err := nodee.EncryptMessage(
		ctx,
		nodee.KeyIdFromPkix(nodeInfo.CertificatePublicKeyPkix),
		nodeCreds,
		nodeInfo,
		opt...,
	)
	if err != nil {
		return nil, fmt.Errorf("(%s) error encrypting message: %w", op, err)
	}

	rootCerts, err := nodetypes.LoadRootCertificates(ctx, storage, opt...)
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

	return &nodetypes.FetchNodeCredentialsResponse{
		EncryptedNodeCredentials:          encryptedBytes,
		EncryptedNodeCredentialsSignature: sigBytes,
		ServerEncryptionPublicKeyBytes:    serverEncryptionPublicKey,
		ServerEncryptionPublicKeyType:     nodeInfo.ServerEncryptionPrivateKeyType,
		Authorized:                        true,
	}, nil
}

// AuthorizeNode authorizes a node that has sent a registration request.
//
// Supported options: WithNodeIdPrefix, WithWrapper (passed through to
// NodeInformation.Store)
func AuthorizeNode(
	ctx context.Context,
	storage nodee.Storage,
	keyId string,
	opt ...nodee.Option,
) error {
	const op = "nodee.noderegistration.AuthorizeNode"
	switch {
	case storage == nil:
		return fmt.Errorf("(%s) nil storage passed in", op)
	case keyId == "":
		return fmt.Errorf("(%s) empty key id passed in", op)
	}

	opts, err := nodee.GetOpts(opt...)
	if err != nil {
		return fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	// log.Println("loading node info with key", keyId)
	nodeInfo, err := nodetypes.LoadNodeInformation(ctx, storage, keyId, opt...)
	if err != nil {
		return fmt.Errorf("(%s) error loading node registration request: %w", op, err)
	}

	certPubKeyRaw, err := x509.ParsePKIXPublicKey(nodeInfo.CertificatePublicKeyPkix)
	if err != nil {
		return fmt.Errorf("(%s) error parsing node certificate public key: %w", op, err)
	}
	certPubKey, ok := certPubKeyRaw.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("(%s) unable to interpret node certificate public key as ed25519 public key", op)
	}

	rootCerts, err := nodetypes.LoadRootCertificates(ctx, storage, opt...)
	if err != nil {
		return fmt.Errorf("(%s) error fetching current root certificates: %w", op, err)
	}

	// Create certificates
	{
		for _, rootCert := range []*nodetypes.RootCertificate{rootCerts.Current, rootCerts.Next} {
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
				DNSNames:     []string{nodee.CommonDnsName},
				KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
				SerialNumber: big.NewInt(mathrand.Int63()),
				NotBefore:    caCert.NotBefore,
				NotAfter:     caCert.NotAfter,
			}

			certificateDer, err := x509.CreateCertificate(opts.WithRandomReader, template, caCert, ed25519.PublicKey(certPubKey), caPrivKey)
			if err != nil {
				return fmt.Errorf("(%s) error creating certificate: %w", op, err)
			}

			nodeInfo.CertificateBundles = append(nodeInfo.CertificateBundles, &nodetypes.CertificateBundle{
				NodeCertificateDer:   certificateDer,
				ServerCertificateDer: rootCert.CertificateDer,
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
		nodeInfo.ServerEncryptionPrivateKeyType = nodetypes.KEYTYPE_KEYTYPE_X25519
	}

	// Now save the authorized status back to the registration request
	nodeInfo.Authorized = true
	if err := nodeInfo.Store(ctx, storage, opt...); err != nil {
		return fmt.Errorf("(%s) error updating registration information: %w", op, err)
	}

	return nil
}
