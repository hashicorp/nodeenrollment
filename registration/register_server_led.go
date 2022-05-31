package registration

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	mathrand "math/rand"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"golang.org/x/crypto/curve25519"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

// RegisterViaServerLedFlow registers a node, creating all keys and
// certificates and returning the full set.
//
// Note: there are currently no fields in the registration request but it is
// required so that if fields are added it is not an API change.
//
// Supported options: WithWrapper (passed through to LoadRootCertificates and
// NodeInformation.Store), WithSkipStorage (useful for tests)
func RegisterViaServerLedFlow(
	ctx context.Context,
	storage nodeenrollment.Storage,
	req *types.ServerLedRegistrationRequest,
	opt ...nodeenrollment.Option,
) (*types.NodeCredentials, error) {
	const op = "nodeenrollment.registration.RegisterViaServerLedFlow"
	switch {
	case req == nil:
		return nil, fmt.Errorf("(%s) nil request", op)
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) nil storage", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	var (
		resp           = new(types.NodeCredentials)
		nodeInfo       = new(types.NodeInformation)
		certPubKey     ed25519.PublicKey
		certPrivKey    ed25519.PrivateKey
		certPubKeyPkix []byte
	)

	rootCerts, err := types.LoadRootCertificates(ctx, storage, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error loading root certificates: %w", op, err)
	}

	// Create certificate key pair
	{
		certPubKey, certPrivKey, err = ed25519.GenerateKey(opts.WithRandomReader)
		if err != nil {
			return nil, fmt.Errorf("(%s) error generating certificate keypair: %w", op, err)
		}
		nodeInfo.CertificatePublicKeyType = types.KEYTYPE_ED25519

		resp.CertificatePrivateKeyPkcs8, err = x509.MarshalPKCS8PrivateKey(certPrivKey)
		if err != nil {
			return nil, fmt.Errorf("(%s) error marshaling certificate private key: %w", op, err)
		}
		resp.CertificatePrivateKeyType = types.KEYTYPE_ED25519

		certPubKeyPkix, nodeInfo.Id, err = nodeenrollment.SubjectKeyInfoAndKeyIdFromPubKey(certPubKey)
		if err != nil {
			return nil, fmt.Errorf("(%s) error fetching public key id: %w", op, err)
		}
		nodeInfo.CertificatePublicKeyPkix = certPubKeyPkix
		resp.CertificatePublicKeyPkix = certPubKeyPkix
	}

	// Create certificate
	{
		for _, rootCert := range []*types.RootCertificate{rootCerts.Current, rootCerts.Next} {
			caCert, caPrivKey, err := rootCert.SigningParams(ctx)
			if err != nil {
				return nil, fmt.Errorf("(%s) error parsing signing parameters from root with id %s: %w", op, rootCert.Id, err)
			}

			template := &x509.Certificate{
				AuthorityKeyId: caCert.SubjectKeyId,
				SubjectKeyId:   certPubKeyPkix,
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
			resp.CertificateBundles = append(resp.CertificateBundles, &types.CertificateBundle{
				CertificateDer:       certificateDer,
				CaCertificateDer:     rootCert.CertificateDer,
				CertificateNotBefore: timestamppb.New(template.NotBefore),
				CertificateNotAfter:  timestamppb.New(template.NotAfter),
			})
			nodeInfo.CertificateBundles = resp.CertificateBundles
		}
	}

	// Create node encryption keys
	{
		resp.EncryptionPrivateKeyBytes = make([]byte, curve25519.ScalarSize)
		n, err := opts.WithRandomReader.Read(resp.EncryptionPrivateKeyBytes)
		switch {
		case err != nil:
			return nil, fmt.Errorf("(%s) error reading random bytes to generate node encryption key: %w", op, err)
		case n != curve25519.ScalarSize:
			return nil, fmt.Errorf("(%s) wrong number of random bytes read when generating node encryption key, expected %d but got %d", op, curve25519.ScalarSize, n)
		}
		resp.EncryptionPrivateKeyType = types.KEYTYPE_X25519

		nodeInfo.EncryptionPublicKeyBytes, err = curve25519.X25519(resp.EncryptionPrivateKeyBytes, curve25519.Basepoint)
		if err != nil {
			return nil, fmt.Errorf("(%s) error performing x25519 operation on generated private key: %w", op, err)
		}
		nodeInfo.EncryptionPublicKeyType = types.KEYTYPE_X25519
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

		resp.ServerEncryptionPublicKeyBytes, err = curve25519.X25519(nodeInfo.ServerEncryptionPrivateKeyBytes, curve25519.Basepoint)
		if err != nil {
			return nil, fmt.Errorf("(%s) error performing x25519 operation on generated private key: %w", op, err)
		}
		resp.ServerEncryptionPublicKeyType = types.KEYTYPE_X25519
	}

	if !opts.WithSkipStorage {
		// At this point everything is generated and both messages are prepared;
		// store the value
		if err := nodeInfo.Store(ctx, storage, opt...); err != nil {
			return nil, fmt.Errorf("(%s) error storing node information: %w", op, err)
		}
	}

	return resp, nil
}
