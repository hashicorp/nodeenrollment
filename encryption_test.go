// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package nodeenrollment

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

type testNode struct {
	keyId    string
	priv     []byte
	otherPub []byte
}

func (t testNode) X25519EncryptionKey() (string, []byte, error) {
	privKey, err := ecdh.X25519().NewPrivateKey(t.priv)
	if err != nil {
		return "", nil, err
	}
	otherPubKey, err := ecdh.X25519().NewPublicKey(t.otherPub)
	if err != nil {
		return "", nil, err
	}
	encKey, err := privKey.ECDH(otherPubKey)
	if err != nil {
		return "", nil, err
	}
	return t.keyId, encKey, err
}

func (t testNode) PreviousX25519EncryptionKey() (string, []byte, error) {
	return "", nil, nil
}

var _ X25519KeyProducer = (*testNode)(nil)

func Test_EncryptionDecryption(t *testing.T) {
	t.Parallel()
	tRequire := require.New(t)
	ctx := context.Background()

	wrapper := aead.TestWrapper(t)

	curve := ecdh.X25519()

	node1Priv, err := curve.GenerateKey(rand.Reader)
	tRequire.NoError(err)
	node1Pub := node1Priv.PublicKey()

	node2Priv, err := curve.GenerateKey(rand.Reader)
	tRequire.NoError(err)
	node2Pub := node2Priv.PublicKey()

	node1 := &testNode{priv: node1Priv.Bytes(), otherPub: node2Pub.Bytes()}
	node2 := &testNode{priv: node2Priv.Bytes(), otherPub: node1Pub.Bytes()}

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
		encryptKeySource   X25519KeyProducer
		decryptKeySource   X25519KeyProducer
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

			_, sharedKeyFromNode, err := tt.node.X25519EncryptionKey()
			subtRequire.NoError(err)

			if tt.otherNode != nil {
				_, sharedKeyFromOtherNode, err := tt.otherNode.X25519EncryptionKey()
				subtRequire.NoError(err)

				subtAssert.Equal(sharedKeyFromNode, sharedKeyFromOtherNode)
				return
			}

			if tt.encryptKeySource != nil {
				tt.encryptKeySource.(*testNode).keyId = tt.encryptId
			}
			ct, err := EncryptMessage(ctx, tt.encryptMsg, tt.encryptKeySource, WithStorageWrapper(tt.encDecWrapper))
			if tt.wantEncErrContains != "" {
				subtRequire.Error(err)
				subtAssert.Contains(err.Error(), tt.wantEncErrContains)
				return
			}
			subtRequire.NoError(err)
			if tt.decryptKeySource != nil {
				tt.decryptKeySource.(*testNode).keyId = tt.decryptId
			}
			err = DecryptMessage(ctx, ct, tt.decryptKeySource, tt.decryptMsg, WithStorageWrapper(tt.encDecWrapper))
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
