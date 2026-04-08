// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package protocol

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/nodeenrollment"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestNewConn(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)

	expectedState, err := structpb.NewStruct(map[string]any{"worker_id": "w_123"})
	require.NoError(err)

	conn, err := NewConn(
		testTLSConn(t),
		nodeenrollment.WithExtraAlpnProtos([]string{"proto-a", "proto-b"}),
		nodeenrollment.WithState(expectedState),
	)
	require.NoError(err)

	require.NoError(conn.Handshake())
	require.NoError(conn.HandshakeContext(context.Background()))
	assert.Equal([]string{"proto-a", "proto-b"}, conn.ClientNextProtos())
	assert.Equal(expectedState, conn.ClientState())
	clientNextProtos := conn.ClientNextProtos()
	clientNextProtos[0] = "mutated"
	assert.Equal([]string{"proto-a", "proto-b"}, conn.ClientNextProtos())

	assert.False(conn.ConnectionState().HandshakeComplete)
	assert.NoError(conn.handshakeErr)
	assert.NotNil(conn.handshakeDone)
	select {
	case <-conn.handshakeDone:
	default:
		t.Fatal("expected NewConn handshakeDone to be closed")
	}
}

func TestConn_NilReceiver(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)

	var conn *Conn

	require.ErrorIs(conn.HandshakeContext(context.Background()), errNilConn)
	assert.ErrorIs(conn.Handshake(), errNilConn)

	_, err := conn.Read(nil)
	assert.ErrorIs(err, errNilConn)

	_, err = conn.Write(nil)
	assert.ErrorIs(err, errNilConn)

	assert.Equal(tls.ConnectionState{}, conn.ConnectionState())
	assert.Nil(conn.ClientNextProtos())
	assert.Nil(conn.ClientState())

	assert.NotPanics(func() {
		conn.startHandshake()
		conn.setClientInfo([]string{"proto-a"}, nil)
	})
}

func TestConn_ZeroValue(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	// Create a conn with a nil embedded net.Conn and a nil handshakeDone channel
	conn := new(Conn)

	assert.ErrorIs(conn.Handshake(), errNilConn)
	assert.ErrorIs(conn.HandshakeContext(context.Background()), errNilConn)

	_, err := conn.Read(nil)
	assert.ErrorIs(err, errNilConn)

	_, err = conn.Write(nil)
	assert.ErrorIs(err, errNilConn)

	assert.Equal(tls.ConnectionState{}, conn.ConnectionState())
	assert.Nil(conn.ClientNextProtos())
	assert.Nil(conn.ClientState())

	assert.NotPanics(func() {
		conn.startHandshake()
		conn.setClientInfo([]string{"proto-a"}, nil)
	})
}

func TestConn_HandshakeStartsOnce(t *testing.T) {
	t.Parallel()
	require, assert := require.New(t), assert.New(t)

	expectedState, err := structpb.NewStruct(map[string]any{"worker_id": "w_123"})
	require.NoError(err)

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	handshakeCalls := new(atomic.Int32)

	conn, err := newConn(testTLSConn(t), func(c *Conn) error {
		handshakeCalls.Add(1)
		c.setClientInfo([]string{"proto-a"}, expectedState)
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return nil
	})
	require.NoError(err)
	assert.Zero(handshakeCalls.Load())

	handshake1 := make(chan error, 1)
	handshake2 := make(chan error, 1)
	handshake3 := make(chan error, 1)
	go func() {
		handshake1 <- conn.Handshake()
	}()
	go func() {
		handshake2 <- conn.Handshake()
	}()
	go func() {
		handshake3 <- conn.Handshake()
	}()

	// wait for handshake to be called
	<-started

	// Even with 3 concurrent handshakes, the handshake function should only
	// be called once until it is released
	assert.EqualValues(1, handshakeCalls.Load())

	time.Sleep(time.Second)

	select {
	case err := <-handshake1:
		t.Fatalf("handshake1 returned before release: %v", err)
	case err := <-handshake2:
		t.Fatalf("handshake2 returned before release: %v", err)
	case err := <-handshake3:
		t.Fatalf("handshake3 returned before release: %v", err)
	default:
	}

	close(release)

	require.NoError(<-handshake1)
	require.NoError(<-handshake2)
	require.NoError(<-handshake3)
	assert.Equal([]string{"proto-a"}, conn.ClientNextProtos())
	assert.Equal(expectedState, conn.ClientState())
	assert.EqualValues(1, handshakeCalls.Load())
	assert.Equal([]string{"proto-a"}, conn.ClientNextProtos())
}

func testTLSConn(t *testing.T) *tls.Conn {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		_ = serverConn.Close()
		_ = clientConn.Close()
	})

	return tls.Server(serverConn, &tls.Config{})
}
