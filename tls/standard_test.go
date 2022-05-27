package tls

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// TestTls validates that we can make connections and that the custom
// verification logic works when using both TLS parameters created via
// RootCertificates -- that is, certificates provisioned on the fly from a
// controller -- and from node cred generated TLS configs.
//
// It also validates the same for node-to-node connections.
//
// The structure of the test is a bit odd because running FailNow in a subtest
// goroutine creates problems, and generally because of the client/server aspect
// of things. So it's a function that tests client/server functionality along
// with (possibly) a custom verify function to ensure that things don't work
// outside of the expected case, and whether or not we expect the handshake to
// succeed based on that verify function.
func TestStandardTls(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage, err := file.NewFileStorage(ctx)
	require.NoError(t, err)
	t.Cleanup(storage.Cleanup)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	node, err := registration.RegisterViaServerLedFlow(ctx, storage, &types.ServerLedRegistrationRequest{})
	require.NoError(t, err)

	t.Log("valid")
	runTest(t, ctx, storage, node, false)

	t.Log("invalid-nonce")
	runTest(t, ctx, storage, node, true, nodeenrollment.WithNonce("foobar"))

	t.Log("invalid-expected-public-key")
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	runTest(t, ctx, storage, node, true, nodeenrollment.WithExpectedPublicKey(pub))

	t.Log("invalid-nil-cert-pool")
	runTest(t, ctx, storage, node, true,
		nodeenrollment.WithTlsVerifyOptionsFunc(
			func(cp *x509.CertPool) x509.VerifyOptions {
				return x509.VerifyOptions{
					DNSName: nodeenrollment.CommonDnsName,
					Roots:   nil,
					KeyUsages: []x509.ExtKeyUsage{
						x509.ExtKeyUsageClientAuth,
						x509.ExtKeyUsageServerAuth,
					},
				}
			},
		),
	)

	t.Log("invalid-name")
	runTest(t, ctx, storage, node, true,
		nodeenrollment.WithTlsVerifyOptionsFunc(
			func(cp *x509.CertPool) x509.VerifyOptions {
				return x509.VerifyOptions{
					DNSName: "invalid",
					Roots:   cp,
					KeyUsages: []x509.ExtKeyUsage{
						x509.ExtKeyUsageClientAuth,
						x509.ExtKeyUsageServerAuth,
					},
				}
			},
		),
	)

	t.Log("invalid-wrong-cert-in-pool")
	// Create a new root set (on new storage since rotating won't do anything
	// right now due to validity windows)
	wrongStorage, err := file.NewFileStorage(ctx)
	require.NoError(t, err)
	t.Cleanup(wrongStorage.Cleanup)
	wrongRoots, err := rotation.RotateRootCertificates(ctx, wrongStorage, nodeenrollment.WithSkipStorage(true))
	require.NoError(t, err)
	wrongRootPool := x509.NewCertPool()
	wrongRootCurrentCert, err := x509.ParseCertificate(wrongRoots.Current.CertificateDer)
	require.NoError(t, err)
	wrongRootPool.AddCert(wrongRootCurrentCert)
	require.NoError(t, err)
	wrongRootNextCert, err := x509.ParseCertificate(wrongRoots.Next.CertificateDer)
	require.NoError(t, err)
	wrongRootPool.AddCert(wrongRootNextCert)
	require.NoError(t, err)
	runTest(t, ctx, storage, node, true,
		nodeenrollment.WithTlsVerifyOptionsFunc(
			func(cp *x509.CertPool) x509.VerifyOptions {
				return x509.VerifyOptions{
					DNSName: nodeenrollment.CommonDnsName,
					Roots:   wrongRootPool,
					KeyUsages: []x509.ExtKeyUsage{
						x509.ExtKeyUsageClientAuth,
						x509.ExtKeyUsageServerAuth,
					},
				}
			},
		),
	)
}

func runTest(t *testing.T, ctx context.Context, storage nodeenrollment.Storage, nodeCreds *types.NodeCredentials, shouldFailHandshake bool, opt ...nodeenrollment.Option) {
	require, assert := require.New(t), assert.New(t)

	opts, err := nodeenrollment.GetOpts(opt...)
	require.NoError(err)

	// Get our client config
	clientTlsConfig, err := ClientConfig(ctx, nodeCreds, opt...)
	require.NoError(err)
	require.NotNil(clientTlsConfig)

	// Pull out the client request and generated nonce and create the generate
	// certs response from it
	clientReqStr, err := CombineFromNextProtos(nodeenrollment.AuthenticateNodeNextProtoV1Prefix, clientTlsConfig.NextProtos)
	require.NoError(err)
	clientReqBytes, err := base64.RawStdEncoding.DecodeString(clientReqStr)
	require.NoError(err)
	var clientReq types.GenerateServerCertificatesRequest
	require.NoError(proto.Unmarshal(clientReqBytes, &clientReq))
	if opts.WithNonce != "" {
		// Turn off signature verification and set nonce to the passed-in value
		clientReq.SkipVerification = true
		clientReq.Nonce = []byte(opts.WithNonce)
	}
	generateRequest, err := GenerateServerCertificates(ctx, storage, &clientReq, opt...)
	require.NoError(err)

	// Get our server config
	serverTlsConfig, err := ServerConfig(ctx, generateRequest, opt...)
	require.NoError(err)
	require.NotNil(serverTlsConfig)
	serverTlsConfig.NextProtos = clientTlsConfig.NextProtos

	// Make the TLS listener
	wg := new(sync.WaitGroup)
	wg.Add(1)
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", serverTlsConfig)
	require.NoError(err)
	dialAddr := listener.Addr().String()

	// Create control logic
	cancelCtx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Minute)
	cancel := func() {
		cancelFunc()
		if err := listener.Close(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Log("error closing listener", err)
		}
	}
	t.Cleanup(cancel)

	// Accept a connection and test handshake on the server side
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				if !strings.Contains(err.Error(), "use of closed network connection") {
					assert.NoError(err)
				}
				cancel()
				return
			}
			select {
			case <-cancelCtx.Done():
				// If we hit this we didn't get through handshaking, ensure we fail
				assert.True(false)
				return
			default:
				tlsConn := conn.(*tls.Conn)
				assert.False(tlsConn.ConnectionState().HandshakeComplete)
				err := tlsConn.HandshakeContext(cancelCtx)
				if shouldFailHandshake {
					assert.Error(err)
					cancel()
					return
				}
				assert.NoError(err)
				assert.True(tlsConn.ConnectionState().HandshakeComplete)
				return
			}
		}
	}()

	// Dial on the client side and also check for errors (expected or not)
	tlsConn, err := tls.Dial("tcp4", dialAddr, clientTlsConfig)
	if shouldFailHandshake {
		assert.Error(err)
		cancel()
		return
	}
	require.NoError(err)
	require.NotNil(tlsConn)
	// Loop and wait for handshake complete
	for {
		var done bool
		select {
		case <-cancelCtx.Done():
			done = true
		case <-time.After(50 * time.Millisecond):
			if tlsConn.ConnectionState().HandshakeComplete {
				done = true
			}
		}
		if done {
			break
		}
	}
	assert.True(tlsConn.ConnectionState().HandshakeComplete)
	cancel()

	wg.Wait()
}
