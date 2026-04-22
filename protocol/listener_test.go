// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/nodeenrollment"
	nodetesting "github.com/hashicorp/nodeenrollment/testing"
	nodetls "github.com/hashicorp/nodeenrollment/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInterceptingListener_TlsHandshakeTimeout(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)

	ctx, fileStorage, _ := nodetesting.CommonTestParams(t)
	baseLn, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(err)
	t.Cleanup(func() {
		_ = baseLn.Close()
	})

	t.Run("default", func(t *testing.T) {
		listener, err := NewInterceptingListener(&InterceptingListenerConfiguration{
			Context:      ctx,
			Storage:      fileStorage,
			BaseListener: baseLn,
		})
		require.NoError(err)
		assert.Equal(nodeenrollment.DefaultTlsHandshakeTimeout, listener.handshakeTimeout)
	})

	t.Run("explicit", func(t *testing.T) {
		listener, err := NewInterceptingListener(&InterceptingListenerConfiguration{
			Context:             ctx,
			Storage:             fileStorage,
			BaseListener:        baseLn,
			TlsHandshakeTimeout: 250 * time.Millisecond,
		})
		require.NoError(err)
		assert.Equal(250*time.Millisecond, listener.handshakeTimeout)
	})

	t.Run("negative-invalid", func(t *testing.T) {
		listener, err := NewInterceptingListener(&InterceptingListenerConfiguration{
			Context:             ctx,
			Storage:             fileStorage,
			BaseListener:        baseLn,
			TlsHandshakeTimeout: -1,
		})
		require.Error(err)
		assert.Nil(listener)
	})
}

func TestInterceptingListener_CloseCancelsBlockedHandshake(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	ctx, fileStorage, nodeCreds := nodetesting.CommonTestParams(t)

	baseLn, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(err)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(err)
	template := &x509.Certificate{
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(0),
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(5 * time.Minute),
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(err)
	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(err)
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)
	baseTlsConf := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certBytes},
			PrivateKey:  priv,
			Leaf:        cert,
		}},
		RootCAs:            certPool,
		InsecureSkipVerify: true,
	}

	authingListener, err := NewInterceptingListener(&InterceptingListenerConfiguration{
		Context:              ctx,
		Storage:              fileStorage,
		BaseListener:         baseLn,
		BaseTlsConfiguration: baseTlsConf,
		TlsHandshakeTimeout:  24 * time.Hour,
	})
	require.NoError(err)

	// Create a channel to capture the server side handshake ctx cancel from the listener close
	serverHandshakeErr := make(chan error, 1)
	go func() {
		conn, err := authingListener.Accept()
		require.NoError(err)

		protoConn := conn.(*Conn)
		serverHandshakeErr <- protoConn.Handshake()
	}()

	clientTlsConfigs, err := nodetls.ClientConfigs(ctx, nodeCreds)
	require.NoError(err)
	require.NotEmpty(clientTlsConfigs)

	stalledClientTlsConf := clientTlsConfigs[0].Clone()
	requestedClientCertificate := make(chan struct{}, 1)
	releaseClientCertificate := make(chan struct{})
	originalGetClientCertificate := stalledClientTlsConf.GetClientCertificate
	stalledClientTlsConf.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		select {
		case requestedClientCertificate <- struct{}{}:
		default:
		}

		<-releaseClientCertificate
		return originalGetClientCertificate(cri)
	}

	stalledConn, err := net.Dial("tcp4", authingListener.Addr().String())
	require.NoError(err)
	defer stalledConn.Close()

	go func() {
		stalledTLSConn := tls.Client(stalledConn, stalledClientTlsConf)
		defer stalledTLSConn.Close()
		stalledTLSConn.HandshakeContext(ctx)
	}()

	<-requestedClientCertificate

	// Client got a request for cert, but serverHandshake should still be blocking
	select {
	case err := <-serverHandshakeErr:
		t.Fatal("server handshake returned before listener close", err)
	default:
	}

	// Ok now close the listener which should cause the handshake to exit server side
	require.NoError(authingListener.Close())

	// Now we should see a context cancelled error from the server handshake
	err = <-serverHandshakeErr
	require.Error(err)
	require.ErrorContains(err, "context canceled")

	// All done lets cleanup
	close(releaseClientCertificate)
}

func TestInterceptingListener_HandshakeTimeout(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)

	ctx, fileStorage, nodeCreds := nodetesting.CommonTestParams(t)

	baseLn, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(err)
	t.Cleanup(func() {
		_ = baseLn.Close()
	})

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(err)
	template := &x509.Certificate{
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign,
		SerialNumber:          big.NewInt(0),
		NotBefore:             time.Now().Add(-30 * time.Second),
		NotAfter:              time.Now().Add(5 * time.Minute),
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(err)
	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(err)
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)
	baseTlsConf := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certBytes},
			PrivateKey:  priv,
			Leaf:        cert,
		}},
		RootCAs:            certPool,
		InsecureSkipVerify: true,
	}

	// Pass our test logger to the listener so we can capture the logs for assertion later
	logBuffer := new(bytes.Buffer)
	logger := hclog.New(&hclog.LoggerOptions{
		Name:   "test-listener",
		Level:  hclog.Trace,
		Output: logBuffer,
	})

	authingListener, err := NewInterceptingListener(&InterceptingListenerConfiguration{
		Context:              ctx,
		Storage:              fileStorage,
		BaseListener:         baseLn,
		BaseTlsConfiguration: baseTlsConf,
		TlsHandshakeTimeout:  50 * time.Millisecond,
		Options: []nodeenrollment.Option{
			nodeenrollment.WithLogger(logger),
		},
	})
	require.NoError(err)
	t.Cleanup(func() {
		_ = authingListener.Close()
	})

	serverHandshakeErr := make(chan error, 1)
	go func() {
		conn, err := authingListener.Accept()
		require.NoError(err)

		protoConn := conn.(*Conn)
		serverHandshakeErr <- protoConn.Handshake()
	}()

	clientTlsConfigs, err := nodetls.ClientConfigs(ctx, nodeCreds)
	require.NoError(err)
	require.NotEmpty(clientTlsConfigs)

	stalledClientTlsConf := clientTlsConfigs[0].Clone()
	requestedClientCertificate := make(chan struct{}, 1)
	releaseClientCertificate := make(chan struct{})
	originalGetClientCertificate := stalledClientTlsConf.GetClientCertificate
	stalledClientTlsConf.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		select {
		case requestedClientCertificate <- struct{}{}:
		default:
		}

		<-releaseClientCertificate
		return originalGetClientCertificate(cri)
	}

	stalledConn, err := net.Dial("tcp4", authingListener.Addr().String())
	require.NoError(err)
	defer stalledConn.Close()

	go func() {
		stalledTLSConn := tls.Client(stalledConn, stalledClientTlsConf)
		defer stalledTLSConn.Close()
		_ = stalledTLSConn.HandshakeContext(ctx)
	}()

	<-requestedClientCertificate

	err = <-serverHandshakeErr
	require.Error(err)

	// Validate we got the context deadline exceeded error
	assert.ErrorContains(err, "context deadline exceeded")

	close(releaseClientCertificate)

	// Validate we see the client_addr metadata in the timeout logs
	assert.Contains(logBuffer.String(), "client_addr="+stalledConn.LocalAddr().String())
	assert.Contains(logBuffer.String(), "error tls handshaking server side")
}
