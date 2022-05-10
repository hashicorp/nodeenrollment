package noderegistration

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	mathrand "math/rand"

	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/nodetypes"
	"golang.org/x/crypto/curve25519"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

// RegisterViaOperatorLedFlow registers a node, creating all keys and
// certificates and returning the full set.
//
// Note: there are currently no fields in the registration request but it is
// required so that if fields are added it is not an API change.
//
// Supported options: WithWrapper (passed through to NodeInformation.Store),
// WithSkipStorage
func RegisterViaOperatorLedFlow(
	ctx context.Context,
	storage nodee.Storage,
	req *nodetypes.OperatorLedRegistrationRequest,
	opt ...nodee.Option,
) (*nodetypes.NodeCredentials, error) {
	const op = "nodee.noderegistration.RegisterViaOperatorLedFlow"
	switch {
	case req == nil:
		return nil, fmt.Errorf("(%s) nil request passed in", op)
	case storage == nil:
		return nil, fmt.Errorf("(%s) nil storage passed in", op)
	}

	opts, err := nodee.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	var (
		resp           = new(nodetypes.NodeCredentials)
		nodeInfo       = new(nodetypes.NodeInformation)
		certPubKey     ed25519.PublicKey
		certPrivKey    ed25519.PrivateKey
		certPubKeyPkix []byte
	)

	rootCerts, err := nodetypes.LoadRootCertificates(ctx, storage, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error loading root certificates: %w", op, err)
	}

	// Create certificate key pair
	{
		certPubKey, certPrivKey, err = ed25519.GenerateKey(opts.WithRandomReader)
		if err != nil {
			return nil, fmt.Errorf("(%s) error generating certificate keypair: %w", op, err)
		}
		nodeInfo.CertificatePublicKeyType = nodetypes.KEYTYPE_KEYTYPE_ED25519

		resp.CertificatePrivateKeyPkcs8, err = x509.MarshalPKCS8PrivateKey(certPrivKey)
		if err != nil {
			return nil, fmt.Errorf("(%s) error marshaling certificate private key: %w", op, err)
		}
		resp.CertificatePrivateKeyType = nodetypes.KEYTYPE_KEYTYPE_ED25519

		certPubKeyPkix, nodeInfo.Id, err = nodee.SubjectKeyInfoAndKeyIdFromPubKey(certPubKey)
		if err != nil {
			return nil, fmt.Errorf("(%s) error fetching public key id: %w", op, err)
		}
		nodeInfo.CertificatePublicKeyPkix = certPubKeyPkix
		resp.CertificatePublicKeyPkix = certPubKeyPkix
	}

	// Create certificate
	{
		for _, rootCert := range []*nodetypes.RootCertificate{rootCerts.Current, rootCerts.Next} {
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
				DNSNames:     []string{nodee.CommonDnsName},
				KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
				SerialNumber: big.NewInt(mathrand.Int63()),
				NotBefore:    caCert.NotBefore,
				NotAfter:     caCert.NotAfter,
			}

			certificateDer, err := x509.CreateCertificate(opts.WithRandomReader, template, caCert, ed25519.PublicKey(certPubKey), caPrivKey)
			if err != nil {
				return nil, fmt.Errorf("(%s) error creating certificate: %w", op, err)
			}
			resp.CertificateBundles = append(resp.CertificateBundles, &nodetypes.CertificateBundle{
				NodeCertificateDer:   certificateDer,
				ServerCertificateDer: rootCert.CertificateDer,
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
		resp.EncryptionPrivateKeyType = nodetypes.KEYTYPE_KEYTYPE_X25519

		nodeInfo.EncryptionPublicKeyBytes, err = curve25519.X25519(resp.EncryptionPrivateKeyBytes, curve25519.Basepoint)
		if err != nil {
			return nil, fmt.Errorf("(%s) error performing x25519 operation on generated private key: %w", op, err)
		}
		nodeInfo.EncryptionPublicKeyType = nodetypes.KEYTYPE_KEYTYPE_X25519
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
		nodeInfo.ServerEncryptionPrivateKeyType = nodetypes.KEYTYPE_KEYTYPE_X25519

		resp.ServerEncryptionPublicKeyBytes, err = curve25519.X25519(nodeInfo.ServerEncryptionPrivateKeyBytes, curve25519.Basepoint)
		if err != nil {
			return nil, fmt.Errorf("(%s) error performing x25519 operation on generated private key: %w", op, err)
		}
		resp.ServerEncryptionPublicKeyType = nodetypes.KEYTYPE_KEYTYPE_X25519
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
