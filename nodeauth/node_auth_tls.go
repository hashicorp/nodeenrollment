package nodeauth

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"strings"

	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/nodetls"
	"github.com/hashicorp/nodeenrollment/nodetypes"
	"google.golang.org/protobuf/proto"
)

// ContainsNodeAuthAlpnProto performs a simple check to see if one of the ALPN
// SupportedProtos is something we can handle here.
func ContainsNodeAuthAlpnProto(protos ...string) bool {
	for _, p := range protos {
		switch {
		case strings.HasPrefix(p, nodee.FetchNodeCredsNextProtoV1Prefix),
			strings.HasPrefix(p, nodee.AuthenticateNodeNextProtoV1Prefix):
			return true
		}
	}
	return false
}

// NodeTlsConfig produces a TLS configuration that can handle credential
// fetching and node authentication. It is intended to be used as part of a
// tls.Config.GetConfigForClient function. It is usable for this purpose as-is,
// or it can be chained to from an existing GetConfigForClient function. Call
// ContainsNodeAuthParams with the tls.ClientHelloInfo to see if this function
// should be invoked and if so invoke it.
//
// currentRootIdFunc should return the current root certificate ID. This allows
// the function to continue to be used as rotation happens without having to
// re-initialize a listener.
//
// It will produce an error if it is called and no appropriate SupportedProtos
// are found.
//
// Supported options: WithWrapper (passed through to LoadRootCertificate)
func NodeTlsConfig(
	ctx context.Context,
	storage nodee.Storage,
	fetchCredsFn FetchCredsFn,
	generateServerCertificatesFn GenerateServerCertificatesFn,
	opt ...nodee.Option,
) func(*tls.ClientHelloInfo) (*tls.Config, error) {
	const op = "nodee.nodeauth.NodeTlsConfig"
	// It's not ideal to only check parameters at call time but
	// GetConfigForClient doesn't really allow anything else.
	return func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if storage == nil {
			return nil, fmt.Errorf("(%s) nil storage input", op)
		}
		if !ContainsNodeAuthAlpnProto(hello.SupportedProtos...) {
			return nil, fmt.Errorf("(%s) no valid alpn supported protos value found", op)
		}

		serverCertsReq := new(nodetypes.GenerateServerCertificatesRequest)
		var protoToReturn string

		for _, p := range hello.SupportedProtos {
			switch {
			case strings.HasPrefix(p, nodee.FetchNodeCredsNextProtoV1Prefix):
				protoString := nodetls.CombineFromNextProtos(nodee.FetchNodeCredsNextProtoV1Prefix, hello.SupportedProtos)
				reqBytes, err := base64.RawStdEncoding.DecodeString(protoString)
				if err != nil {
					return nil, fmt.Errorf("(%s) error decoding fetch next proto", op)
				}
				req := new(nodetypes.FetchNodeCredentialsRequest)
				if err := proto.Unmarshal(reqBytes, req); err != nil {
					return nil, fmt.Errorf("(%s) error unmarshaling common name value: %w", op, err)
				}
				fetchResp, err := fetchCredsFn(ctx, storage, req, opt...)
				if err != nil {
					return nil, fmt.Errorf("(%s) error handling fetch creds: %w", op, err)
				}
				if fetchResp.Authorized {
					fetchRespBytes, err := proto.Marshal(fetchResp)
					if err != nil {
						return nil, fmt.Errorf("(%s) error marshaling fetch response: %w", op, err)
					}
					serverCertsReq.CommonName = base64.RawStdEncoding.EncodeToString(fetchRespBytes)
				}
				var reqInfo nodetypes.FetchNodeCredentialsInfo
				if err := proto.Unmarshal(req.Bundle, &reqInfo); err != nil {
					return nil, fmt.Errorf("(%s) cannot unmarshal request info: %w", op, err)
				}
				serverCertsReq.SkipVerification = true
				serverCertsReq.Nonce = reqInfo.Nonce
				serverCertsReq.CertificatePublicKeyPkix = reqInfo.CertificatePublicKeyPkix
				protoToReturn = p
				// log.Println("is fetch")

			case strings.HasPrefix(p, nodee.AuthenticateNodeNextProtoV1Prefix):
				// log.Println("not fetch, auth")
				protoString := nodetls.CombineFromNextProtos(nodee.AuthenticateNodeNextProtoV1Prefix, hello.SupportedProtos)
				reqBytes, err := base64.RawStdEncoding.DecodeString(protoString)
				if err != nil {
					return nil, fmt.Errorf("(%s) error decoding auth next proto", op)
				}
				if err := proto.Unmarshal(reqBytes, serverCertsReq); err != nil {
					return nil, fmt.Errorf("(%s) error unmarshaling common name value: %w", op, err)
				}
				protoToReturn = p

			default:
				continue
			}

			// If we're here we found one of our known protos so break out of
			// the for loop and finish
			break
		}

		certResp, err := generateServerCertificatesFn(ctx, storage, serverCertsReq, opt...)
		if err != nil {
			return nil, fmt.Errorf("(%s) error generating server-side certificate: %w", op, err)
		}

		// Ensure that the key we just verified is the one presented on the
		// client certificate
		opt = append(opt, nodee.WithExpectedPublicKey(serverCertsReq.CertificatePublicKeyPkix))

		tlsConf, err := nodetls.TlsServerConfig(ctx, certResp, opt...)
		if err != nil {
			return nil, fmt.Errorf("(%s) error generating root tls config: %w", op, err)
		}

		tlsConf.NextProtos = []string{protoToReturn}
		return tlsConf, nil
	}
}
