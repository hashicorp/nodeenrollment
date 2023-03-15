// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package net_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/nodeenrollment"
	nodeenet "github.com/hashicorp/nodeenrollment/net"
	"github.com/hashicorp/nodeenrollment/protocol"
	nodetesting "github.com/hashicorp/nodeenrollment/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
)

func TestSplitListener(t *testing.T) {
	t.Run("with-non-specific", func(t *testing.T) {
		testSplitListener(t, true, false)
	})
	t.Run("with-non-specific-returning-nativeconn", func(t *testing.T) {
		testSplitListener(t, true, true)
	})
	t.Run("without-non-specific", func(t *testing.T) {
		testSplitListener(t, false, false)
	})
}

func testSplitListener(t *testing.T, withNonSpecific, withNativeConns bool) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)

	ctx, fileStorage, _ := nodetesting.CommonTestParams(t)

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
	// Test that it's the same listener
	unauthLn2, err := splitListener.GetListener(nodeenet.UnauthenticatedNextProto)
	require.NoError(err)
	require.Equal(unauthLn, unauthLn2)

	const testClientNextProtoValue = "expected-val"
	expLn, err := splitListener.GetListener(testClientNextProtoValue, nodeenrollment.WithNativeConns(withNativeConns))
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
			conn, err := expLn.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					expListenerReturnedDone.Store(true)
					return
				}
				expListenerReturnedErr.Store(err.Error())
				return
			}
			switch conn.(type) {
			case *tls.Conn:
				if withNativeConns {
					expListenerReturnedErr.Store("expected native conns, got tls conn")
				}
			case *protocol.Conn:
				if !withNativeConns {
					expListenerReturnedErr.Store("expected tls conns, got native conn")
				}
			default:
				expListenerReturnedErr.Store(fmt.Sprintf("unknown conn type: %T", conn))
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

func TestIngressListener(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)
	ctx := context.Background()

	// Create the base listener
	baseLn1, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(err)
	baseLn2, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(err)

	conns := new(atomic.Int32)
	listenerReturnedDone := new(atomic.Bool)
	listenerReturnedErr := new(atomic.String)

	mxLn, err := nodeenet.NewMultiplexingListener(ctx, baseLn1.Addr())
	require.NoError(err)
	require.NoError(mxLn.IngressListener(baseLn1))
	require.NoError(mxLn.IngressListener(baseLn2))

	wg := new(sync.WaitGroup)
	wg.Add(1)

	go func() {
		defer wg.Done()
		for {
			_, err := mxLn.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					listenerReturnedDone.Store(true)
					return
				}
				listenerReturnedErr.Store(err.Error())
				return
			}
			conns.Add(1)
		}
	}()

	for i := 0; i < 30; i++ {
		var conn net.Conn
		var err error
		switch {
		case i%2 == 0:
			conn, err = net.Dial("tcp4", baseLn1.Addr().String())
		default:
			conn, err = net.Dial("tcp4", baseLn2.Addr().String())
		}

		require.NoError(err)
		require.NotNil(conn, i)
		require.NoError(conn.Close())
	}

	for i := 0; i < 10; i++ {
		conn := &net.TCPConn{}
		mxLn.IngressConn(conn, nil)
	}

	time.Sleep(3 * time.Second)

	require.NoError(baseLn1.Close())
	require.NoError(baseLn2.Close())
	require.NoError(mxLn.Close())
	wg.Wait()

	assert.True(listenerReturnedDone.Load())
	assert.Empty(listenerReturnedErr.Load())
	assert.EqualValues(40, conns.Load())
}
