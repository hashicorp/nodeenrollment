package tls

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	mathrand "math/rand"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/types"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GenerateServerCertificates issues contemporaneous certificates for TLS
// connections from one or more root certificates.
//
// Valid options: WithRandomReader, WithWrapper (passed through to
// LoadNodeInformation and LoadRootCertificates)
func GenerateServerCertificates(
	ctx context.Context,
	storage nodeenrollment.Storage,
	req *types.GenerateServerCertificatesRequest,
	opt ...nodeenrollment.Option,
) (*types.GenerateServerCertificatesResponse, error) {
	const op = "nodeenrollment.tls.GenerateServerCertificates"

	switch {
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) nil storage", op)
	case req == nil:
		return nil, fmt.Errorf("(%s) nil request", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	// We don't have a stored key to use for validation if we haven't authorized
	// the node yet, so in the fetch case we skip this step (we've still
	// validated, earlier, that the bundle is internally consistent; that the
	// signature matches the public key _on the request_ itself).
	if !req.SkipVerification {
		switch {
		case len(req.Nonce) == 0:
			return nil, fmt.Errorf("(%s) empty nonce", op)
		case len(req.NonceSignature) == 0:
			return nil, fmt.Errorf("(%s) empty nonce signature", op)
		}
		// Ensure node is authorized
		keyId, err := nodeenrollment.KeyIdFromPkix(req.CertificatePublicKeyPkix)
		if err != nil {
			return nil, fmt.Errorf("(%s) error deriving key id: %w", op, err)
		}
		nodeInfo, err := types.LoadNodeInformation(ctx, storage, keyId, opt...)
		if err != nil {
			return nil, fmt.Errorf("(%s) error loading node information: %w", op, err)
		}
		// Validate the nonce
		nodePubKeyRaw, err := x509.ParsePKIXPublicKey(nodeInfo.CertificatePublicKeyPkix)
		if err != nil {
			return nil, fmt.Errorf("(%s) node public key cannot be parsed: %w", op, err)
		}
		nodePubKey, ok := nodePubKeyRaw.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("(%s) node public key cannot be interpreted as ed25519 public key: %w", op, err)
		}
		if !ed25519.Verify(nodePubKey, req.Nonce, req.NonceSignature) {
			return nil, fmt.Errorf("(%s) nonce signature verification failed", op)
		}
	}

	// Now we're going to load the roots, generate a new key, and create a set
	// of certificates to use for whatever is acting as the server side to
	// present to the node (client) side
	roots, err := types.LoadRootCertificates(ctx, storage, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error loading root certificates: %w", op, err)
	}

	pubKey, privKey, err := ed25519.GenerateKey(opts.WithRandomReader)
	if err != nil {
		return nil, fmt.Errorf("(%s) error generating just-in-time cert key: %w", op, err)
	}

	resp := &types.GenerateServerCertificatesResponse{
		CertificatePrivateKeyType: types.KEYTYPE_ED25519,
		CertificateBundles:        make([]*types.CertificateBundle, 0, 2),
	}
	resp.CertificatePrivateKeyPkcs8, err = x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("(%s) error marshaling just-in-time cert key: %w", op, err)
	}
	resp.CertificatePrivateKeyType = types.KEYTYPE_ED25519

	for _, rootCert := range []*types.RootCertificate{roots.Current, roots.Next} {
		serverCert, signer, err := rootCert.SigningParams(ctx)
		if err != nil {
			return nil, fmt.Errorf("(%s) error getting signing params: %w", op, err)
		}

		template := &x509.Certificate{
			AuthorityKeyId: serverCert.SubjectKeyId,
			SubjectKeyId:   req.CertificatePublicKeyPkix,
			ExtKeyUsage: []x509.ExtKeyUsage{
				x509.ExtKeyUsageServerAuth,
			},
			Subject: pkix.Name{
				CommonName: nodeenrollment.CommonDnsName,
			},
			DNSNames:     []string{nodeenrollment.CommonDnsName},
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
			SerialNumber: big.NewInt(mathrand.Int63()),
			NotBefore:    serverCert.NotBefore,
			NotAfter:     serverCert.NotAfter,
		}
		if len(req.Nonce) > 0 {
			template.DNSNames = append(template.DNSNames, base64.RawStdEncoding.EncodeToString(req.Nonce))
		}
		if req.CommonName != "" {
			template.Subject.CommonName = req.CommonName
		}

		leafCert, err := x509.CreateCertificate(opts.WithRandomReader, template, serverCert, pubKey, signer)
		if err != nil {
			return nil, fmt.Errorf("(%s) error creating certificate: %w", op, err)
		}

		resp.CertificateBundles = append(resp.CertificateBundles, &types.CertificateBundle{
			CertificateDer:       leafCert,
			CaCertificateDer:     serverCert.Raw,
			CertificateNotBefore: timestamppb.New(serverCert.NotBefore),
			CertificateNotAfter:  timestamppb.New(serverCert.NotAfter),
		})
	}

	return resp, nil
}

// ServerConfig takes in a generate response and turns it into a server-side TLS
// configuration
//
// Supported options: none, although options passed in here will be passed
// through to the standard TLS configuration function (useful for tests,
// mainly)
func ServerConfig(
	ctx context.Context,
	in *types.GenerateServerCertificatesResponse,
	opt ...nodeenrollment.Option,
) (*tls.Config, error) {
	const op = "nodeenrollment.tls.ServerConfig"

	switch {
	case in == nil:
		return nil, fmt.Errorf("(%s) nil input", op)
	case len(in.CertificatePrivateKeyPkcs8) == 0:
		return nil, fmt.Errorf("(%s) nil private key in input", op)
	case in.CertificatePrivateKeyType != types.KEYTYPE_ED25519:
		return nil, fmt.Errorf("(%s) unsupported private key type in input", op)
	case len(in.CertificateBundles) != 2:
		return nil, fmt.Errorf("(%s) invalid input certificate bundles, wanted 2 bundles, got %d", op, len(in.CertificateBundles))
	}

	privKey, err := x509.ParsePKCS8PrivateKey(in.CertificatePrivateKeyPkcs8)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing private key: %w", op, err)
	}

	var tlsCerts []tls.Certificate
	rootPool := x509.NewCertPool()

	for _, certBundle := range in.CertificateBundles {
		leafCert, err := x509.ParseCertificate(certBundle.CertificateDer)
		if err != nil {
			return nil, fmt.Errorf("(%s) error parsing leaf certificate: %w", op, err)
		}

		serverCert, err := x509.ParseCertificate(certBundle.CaCertificateDer)
		if err != nil {
			return nil, fmt.Errorf("(%s) error parsing server certificate: %w", op, err)
		}

		rootPool.AddCert(serverCert)

		tlsCerts = append(tlsCerts, tls.Certificate{
			Certificate: [][]byte{
				leafCert.Raw,
				serverCert.Raw,
			},
			PrivateKey: privKey,
			Leaf:       leafCert,
		})
	}

	tlsConf, err := standardTlsConfig(ctx, tlsCerts, rootPool, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error generating standard tls config: %w", op, err)
	}

	return tlsConf, nil
}
