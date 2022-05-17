package nodeenrollment

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

type testNode struct {
	priv     []byte
	otherPub []byte
}

func (t testNode) X25519EncryptionKey() ([]byte, error) {
	return curve25519.X25519(t.priv, t.otherPub)
}

var _ X25519Producer = (*testNode)(nil)

func Test_EncryptionDecryption(t *testing.T) {
	t.Parallel()
	tRequire := require.New(t)
	ctx := context.Background()

	wrapper := aead.TestWrapper(t)

	node1Priv := make([]byte, curve25519.ScalarSize)
	n, err := rand.Read(node1Priv)
	tRequire.NoError(err)
	tRequire.Equal(n, curve25519.ScalarSize)

	node1Pub, err := curve25519.X25519(node1Priv, curve25519.Basepoint)
	tRequire.NoError(err)

	node2Priv := make([]byte, curve25519.ScalarSize)
	n, err = rand.Read(node2Priv)
	tRequire.NoError(err)
	tRequire.Equal(n, curve25519.ScalarSize)

	node2Pub, err := curve25519.X25519(node2Priv, curve25519.Basepoint)
	tRequire.NoError(err)

	node1 := &testNode{priv: node1Priv, otherPub: node2Pub}
	node2 := &testNode{priv: node2Priv, otherPub: node1Pub}

	encryptMsg := &wrapping.BlobInfo{
		Ciphertext: []byte("foo"),
		Iv:         []byte("bar"),
		Hmac:       []byte("baz"),
	}

	tests := []struct {
		name               string
		node               *testNode
		otherNode          *testNode
		encryptId          string
		decryptId          string
		encryptMsg         proto.Message
		decryptMsg         proto.Message
		encryptKeySource   X25519Producer
		decryptKeySource   X25519Producer
		encDecWrapper      wrapping.Wrapper
		wantErrContains    string
		wantEncErrContains string
		wantDecErrContains string
	}{
		{
			name:             "valid",
			node:             node1,
			encryptId:        "foo",
			decryptId:        "foo",
			encryptMsg:       encryptMsg,
			decryptMsg:       new(wrapping.BlobInfo),
			encryptKeySource: node1,
			decryptKeySource: node1,
		},
		{
			name:             "valid-with-wrapper",
			node:             node1,
			encryptId:        "foo",
			decryptId:        "foo",
			encryptMsg:       encryptMsg,
			decryptMsg:       new(wrapping.BlobInfo),
			encryptKeySource: node1,
			decryptKeySource: node1,
			encDecWrapper:    wrapper,
		},
		{
			name:               "mismatched-id",
			node:               node1,
			encryptId:          "foo",
			decryptId:          "bar",
			encryptMsg:         encryptMsg,
			decryptMsg:         new(wrapping.BlobInfo),
			encryptKeySource:   node1,
			decryptKeySource:   node1,
			wantDecErrContains: "message authentication failed",
		},
		{
			name:               "empty-encrypt-msg",
			node:               node1,
			encryptId:          "foo",
			decryptId:          "bar",
			encryptMsg:         nil,
			decryptMsg:         new(wrapping.BlobInfo),
			encryptKeySource:   node1,
			decryptKeySource:   node1,
			wantEncErrContains: "incoming message is nil",
		},
		{
			name:               "empty-decrypt-msg",
			node:               node1,
			encryptId:          "foo",
			decryptId:          "bar",
			encryptMsg:         encryptMsg,
			decryptMsg:         nil,
			encryptKeySource:   node1,
			decryptKeySource:   node1,
			wantDecErrContains: "incoming result message is nil",
		},
		{
			name:               "empty-encrypt-keyproducer",
			node:               node1,
			encryptId:          "foo",
			decryptId:          "bar",
			encryptMsg:         encryptMsg,
			decryptMsg:         new(wrapping.BlobInfo),
			encryptKeySource:   nil,
			decryptKeySource:   node1,
			wantEncErrContains: "incoming key source is nil",
		},
		{
			name:               "empty-decrypt-keyproducer",
			node:               node1,
			encryptId:          "foo",
			decryptId:          "bar",
			encryptMsg:         encryptMsg,
			decryptMsg:         new(wrapping.BlobInfo),
			encryptKeySource:   node1,
			decryptKeySource:   nil,
			wantDecErrContains: "incoming key source is nil",
		},
		{
			name:             "ensure-same-keys",
			node:             node1,
			otherNode:        node2,
			encryptId:        "foo",
			decryptId:        "foo",
			encryptKeySource: node1,
			decryptKeySource: node1,
			wantErrContains:  "unknown type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subtAssert, subtRequire := assert.New(t), require.New(t)

			sharedKeyFromNode, err := tt.node.X25519EncryptionKey()
			subtRequire.NoError(err)

			if tt.otherNode != nil {
				sharedKeyFromOtherNode, err := tt.otherNode.X25519EncryptionKey()
				subtRequire.NoError(err)

				subtAssert.Equal(sharedKeyFromNode, sharedKeyFromOtherNode)
				return
			}

			ct, err := EncryptMessage(ctx, tt.encryptId, tt.encryptMsg, tt.encryptKeySource, WithWrapper(tt.encDecWrapper))
			if tt.wantEncErrContains != "" {
				subtRequire.Error(err)
				subtAssert.Contains(err.Error(), tt.wantEncErrContains)
				return
			}
			subtRequire.NoError(err)
			err = DecryptMessage(ctx, tt.decryptId, ct, tt.decryptKeySource, tt.decryptMsg, WithWrapper(tt.encDecWrapper))
			if tt.wantDecErrContains != "" {
				subtRequire.Error(err)
				subtAssert.Contains(err.Error(), tt.wantDecErrContains)
				return
			}
			subtRequire.NoError(err)
			subtAssert.Empty(cmp.Diff(tt.encryptMsg, tt.decryptMsg, protocmp.Transform()))
		})
	}
}
