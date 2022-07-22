package net_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/nodeenrollment"
	nodeenet "github.com/hashicorp/nodeenrollment/net"
	"github.com/hashicorp/nodeenrollment/protocol"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
)

func TestSplitListener(t *testing.T) {
	t.Run("with-non-specific", func(t *testing.T) {
		testSplitListener(t, true)
	})
	t.Run("without-non-specific", func(t *testing.T) {
		testSplitListener(t, false)
	})
}

func testSplitListener(t *testing.T, withNonSpecific bool) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()

	fileStorage, err := file.New(ctx)
	require.NoError(err)
	t.Cleanup(fileStorage.Cleanup)

	// Get a TLS stack. Hey, we can use other parts of the lib!
	_, err = rotation.RotateRootCertificates(ctx, fileStorage)
	require.NoError(err)
	nodeCreds, err := registration.RegisterViaServerLedFlow(ctx, fileStorage, &types.ServerLedRegistrationRequest{})
	require.NoError(err)
	nodeCreds.Id = string(nodeenrollment.CurrentId)
	require.NoError(nodeCreds.Store(ctx, fileStorage))

	// Create the base listener
	baseLn, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(err)

	// Create a test cert
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
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{certBytes},
				PrivateKey:  priv,
				Leaf:        cert,
			},
		},
		RootCAs:            certPool,
		InsecureSkipVerify: true,
	}

	// Create the intercepting listener
	authingListener, err := protocol.NewInterceptingListener(&protocol.InterceptingListenerConfiguration{
		Context:              ctx,
		Storage:              fileStorage,
		BaseListener:         baseLn,
		BaseTlsConfiguration: baseTlsConf,
	})
	require.NoError(err)

	authConns := new(atomic.Int32)
	authListenerReturnedDone := new(atomic.Bool)
	authListenerReturnedErr := new(atomic.String)
	unauthConns := new(atomic.Int32)
	unauthListenerReturnedDone := new(atomic.Bool)
	unauthListenerReturnedErr := new(atomic.String)
	expConns := new(atomic.Int32)
	expListenerReturnedDone := new(atomic.Bool)
	expListenerReturnedErr := new(atomic.String)

	// First check that a non-protocol.InterceptinListener returns an error,
	// then construct the real thing
	nonNodeeListener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(err)
	_, err = nodeenet.NewSplitListener(nonNodeeListener)
	require.NoError(nonNodeeListener.Close())
	require.Error(err)
	splitListener, err := nodeenet.NewSplitListener(authingListener)
	require.NoError(err)

	numWgVals := 3

	var authLn net.Listener
	if withNonSpecific {
		authLn, err = splitListener.GetListener(nodeenet.AuthenticatedNonSpecificNextProto)
		require.NoError(err)
		numWgVals = 4
	}
	unauthLn, err := splitListener.GetListener(nodeenet.UnauthenticatedNextProto)
	require.NoError(err)
	const testClientNextProtoValue = "expected-val"
	expLn, err := splitListener.GetListener(testClientNextProtoValue)
	require.NoError(err)

	wg := new(sync.WaitGroup)
	wg.Add(numWgVals)

	if withNonSpecific {
		go func() {
			defer wg.Done()
			for {
				_, err := authLn.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						authListenerReturnedDone.Store(true)
						return
					}
					authListenerReturnedErr.Store(err.Error())
					return
				}
				authConns.Add(1)
			}
		}()
	}

	go func() {
		defer wg.Done()
		for {
			_, err := unauthLn.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					unauthListenerReturnedDone.Store(true)
					return
				}
				unauthListenerReturnedErr.Store(err.Error())
				return
			}
			unauthConns.Add(1)
		}
	}()

	go func() {
		defer wg.Done()
		for {
			_, err := expLn.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					expListenerReturnedDone.Store(true)
					return
				}
				expListenerReturnedErr.Store(err.Error())
				return
			}
			expConns.Add(1)
		}
	}()

	startErr := new(atomic.String)
	go func() {
		defer wg.Done()
		startErr.Store(splitListener.Start().Error())
	}()

	for i := 0; i < 30; i++ {
		var conn net.Conn
		var err error
		switch {
		case i%5 == 0:
			conn, err = protocol.Dial(ctx, fileStorage, authingListener.Addr().String(), nodeenrollment.WithExtraAlpnProtos([]string{testClientNextProtoValue}))
		case i%3 == 0:
			conn, err = protocol.Dial(ctx, fileStorage, authingListener.Addr().String())
		default:
			conn, err = tls.Dial("tcp4", authingListener.Addr().String(), baseTlsConf)
		}

		require.NoError(err)
		require.NotNil(conn, i)
		require.NoError(conn.Close())
	}

	time.Sleep(5 * time.Second)

	require.NoError(authingListener.Close())
	wg.Wait()

	assert.Contains(startErr.Load(), net.ErrClosed.Error())

	// If withNonSpecific is false, we'll see the branch exercised in test
	// coverage
	if withNonSpecific {
		assert.True(authListenerReturnedDone.Load())
		assert.Empty(authListenerReturnedErr.Load())
		assert.EqualValues(8, authConns.Load())
	}

	assert.True(unauthListenerReturnedDone.Load())
	assert.Empty(unauthListenerReturnedErr.Load())
	assert.EqualValues(16, unauthConns.Load())

	assert.True(expListenerReturnedDone.Load())
	assert.Empty(expListenerReturnedErr.Load())
	assert.EqualValues(6, expConns.Load())
}
