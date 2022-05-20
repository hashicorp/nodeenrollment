package splitlistener

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/hashicorp/nodeenrollment/storage/file"
	nodetls "github.com/hashicorp/nodeenrollment/tls"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/atomic"
	"google.golang.org/protobuf/proto"
)

func TestSplitListener(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	fileStorage, err := file.NewFileStorage(ctx)
	require.NoError(t, err)
	t.Cleanup(fileStorage.Cleanup)

	// Get a TLS stack. Hey, we can use other parts of the lib!
	_, err = rotation.RotateRootCertificates(ctx, fileStorage)
	require.NoError(t, err)
	nodeCreds, err := registration.RegisterViaOperatorLedFlow(ctx, fileStorage, &types.OperatorLedRegistrationRequest{})
	require.NoError(t, err)

	clientTlsConfig, err := nodetls.ClientConfig(ctx, nodeCreds)
	require.NoError(t, err)
	require.NotNil(t, clientTlsConfig)

	// Pull out the client request and generated nonce and create the generate
	// certs response from it
	clientReqStr := nodetls.CombineFromNextProtos(nodeenrollment.AuthenticateNodeNextProtoV1Prefix, clientTlsConfig.NextProtos)
	clientReqBytes, err := base64.RawStdEncoding.DecodeString(clientReqStr)
	require.NoError(t, err)
	var clientReq types.GenerateServerCertificatesRequest
	require.NoError(t, proto.Unmarshal(clientReqBytes, &clientReq))
	generateRequest, err := nodetls.GenerateServerCertificates(ctx, fileStorage, &clientReq)
	require.NoError(t, err)

	// Get our server config
	serverTlsConfig, err := nodetls.ServerConfig(ctx, generateRequest)
	require.NoError(t, err)
	require.NotNil(t, serverTlsConfig)
	serverTlsConfig.NextProtos = append(clientTlsConfig.NextProtos, "foobar")

	// Create the base listener
	tlsListener, err := tls.Listen("tcp4", "127.0.0.1:0", serverTlsConfig)
	require.NoError(t, err)

	nodeeConns := new(atomic.Int32)
	nodeeListenerReturnedDone := new(atomic.Bool)
	nodeeListenerReturnedErr := new(atomic.String)
	otherConns := new(atomic.Int32)
	otherListenerReturnedDone := new(atomic.Bool)
	otherListenerReturnedErr := new(atomic.String)

	splitListener := NewSplitListener(tlsListener)

	wg := new(sync.WaitGroup)
	wg.Add(3)

	go func() {
		defer wg.Done()
		ln := splitListener.NodeEnrollmentListener()
		for {
			_, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					nodeeListenerReturnedDone.Store(true)
					return
				}
				nodeeListenerReturnedErr.Store(err.Error())
				return
			}
			nodeeConns.Add(1)
		}
	}()

	go func() {
		defer wg.Done()
		ln := splitListener.OtherListener()
		for {
			_, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					otherListenerReturnedDone.Store(true)
					return
				}
				otherListenerReturnedErr.Store(err.Error())
				return
			}
			otherConns.Add(1)
		}
	}()

	startErr := new(atomic.String)
	go func() {
		defer wg.Done()
		startErr.Store(splitListener.Start().Error())
	}()

	for i := 0; i < 10; i++ {
		currTls := clientTlsConfig.Clone()
		// Test out both the not-our-alpn-protos case and the empty case
		if i%2 == 0 {
			currTls.NextProtos = []string{"foobar"}
		}
		if i%4 == 0 {
			currTls.NextProtos = nil
		}
		conn, err := tls.Dial("tcp4", tlsListener.Addr().String(), currTls)
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	}

	require.NoError(t, splitListener.Stop())
	wg.Wait()

	assert.Equal(t, net.ErrClosed.Error(), startErr.Load())
	assert.True(t, nodeeListenerReturnedDone.Load())
	assert.True(t, otherListenerReturnedDone.Load())
	assert.Empty(t, nodeeListenerReturnedErr.Load())
	assert.Empty(t, otherListenerReturnedErr.Load())
	assert.EqualValues(t, 5, nodeeConns.Load())
	assert.EqualValues(t, 5, otherConns.Load())
}
