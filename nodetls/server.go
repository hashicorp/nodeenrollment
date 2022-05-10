package nodetls

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

	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/nodetypes"
)

// GenerateServerCertificates issues contemporaneous certificates for TLS
// connections from one or more root certificates.
//
// Valid options: WithRandomReader, WithWrapper(pased through to
// LoadNodeInformation)
func GenerateServerCertificates(
	ctx context.Context,
	storage nodee.Storage,
	req *nodetypes.GenerateServerCertificatesRequest,
	opt ...nodee.Option,
) (ret *nodetypes.GenerateServerCertificatesResponse, retErr error) {
	const op = "nodee.nodetls.GenerateServerCertificates"

	switch {
	case storage == nil:
		return nil, fmt.Errorf("(%s) nil storage passed in", op)
	case req == nil:
		return nil, fmt.Errorf("(%s) nil request passed in", op)
	}

	opts, err := nodee.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	if !req.SkipVerification {
		switch {
		case len(req.Nonce) == 0:
			return nil, fmt.Errorf("(%s) empty nonce passed in", op)
		case len(req.NonceSignature) == 0:
			return nil, fmt.Errorf("(%s) empty nonce signature passed in", op)
		}
		// Ensure node is authorized
		nodeInfo, err := nodetypes.LoadNodeInformation(ctx, storage, nodee.KeyIdFromPkix(req.CertificatePublicKeyPkix), opt...)
		if err != nil {
			return nil, fmt.Errorf("(%s) error loading node information: %w", op, err)
		}
		if !nodeInfo.Authorized {
			return nil, fmt.Errorf("(%s) node is not authorized", op)
		}
		// Validate the nonce
		nodePubKey, err := x509.ParsePKIXPublicKey(nodeInfo.CertificatePublicKeyPkix)
		if err != nil {
			return nil, fmt.Errorf("(%s) node public key cannot be parsed: %w", op, err)
		}
		if !ed25519.Verify(nodePubKey.(ed25519.PublicKey), req.Nonce, req.NonceSignature) {
			return nil, fmt.Errorf("(%s) request bytes signature verification failed", op)
		}
	}

	roots, err := nodetypes.LoadRootCertificates(ctx, storage, opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error loading root certificates: %w", op, err)
	}

	pubKey, privKey, err := ed25519.GenerateKey(opts.WithRandomReader)
	if err != nil {
		return nil, fmt.Errorf("(%s) error generating just-in-time cert key: %w", op, err)
	}

	resp := &nodetypes.GenerateServerCertificatesResponse{
		CertificatePrivateKeyType: nodetypes.KEYTYPE_KEYTYPE_ED25519,
		CertificateBundles:        make([]*nodetypes.CertificateBundle, 0, 2),
	}
	resp.CertificatePrivateKeyPkcs8, err = x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("(%s) error marshaling just-in-time cert key: %w", op, err)
	}
	resp.CertificatePrivateKeyType = nodetypes.KEYTYPE_KEYTYPE_ED25519

	for _, rootCert := range []*nodetypes.RootCertificate{roots.Current, roots.Next} {
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
				CommonName: nodee.CommonDnsName,
			},
			DNSNames:     []string{nodee.CommonDnsName},
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

		resp.CertificateBundles = append(resp.CertificateBundles, &nodetypes.CertificateBundle{
			NodeCertificateDer:   leafCert,
			ServerCertificateDer: serverCert.Raw,
		})
	}

	return resp, nil
}

func TlsServerConfig(
	ctx context.Context,
	resp *nodetypes.GenerateServerCertificatesResponse,
	opt ...nodee.Option,
) (*tls.Config, error) {
	const op = "nodee.nodetls.TlsServerConfig"

	privKey, err := x509.ParsePKCS8PrivateKey(resp.CertificatePrivateKeyPkcs8)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing private key: %w", op, err)
	}

	var tlsCerts []tls.Certificate
	rootPool := x509.NewCertPool()

	for _, certBundle := range resp.CertificateBundles {
		leafCert, err := x509.ParseCertificate(certBundle.NodeCertificateDer)
		if err != nil {
			return nil, fmt.Errorf("(%s) error parsing leaf certificate: %w", op, err)
		}

		serverCert, err := x509.ParseCertificate(certBundle.ServerCertificateDer)
		if err != nil {
			return nil, fmt.Errorf("(%s) error parsing server certificate: %w", op, err)
		}
		// log.Println(op, "adding server CA cert serial", serverCert.SerialNumber.String())

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
