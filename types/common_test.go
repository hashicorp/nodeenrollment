// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"crypto/ecdh"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestValidateMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		msg             proto.Message
		wantErrContains string
	}{
		{
			name: "valid-node-credentials",
			msg:  new(NodeCredentials),
		},
		{
			name: "valid-node-information",
			msg:  new(NodeInformation),
		},
		{
			name: "valid-root-certificates",
			msg:  new(RootCertificates),
		},
		{
			name:            "nil-msg",
			wantErrContains: "nil message",
		},
		{
			name:            "unknown-msg",
			msg:             new(FetchNodeCredentialsResponse),
			wantErrContains: "unknown message type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subtAssert, subtRequire := assert.New(t), require.New(t)
			err := ValidateMessage(tt.msg)
			switch tt.wantErrContains {
			case "":
				subtAssert.NoError(err)
			default:
				subtRequire.Error(err)
				subtAssert.Contains(err.Error(), tt.wantErrContains)
			}
		})
	}
}

func TestDeriveSharedX25519EncryptionKey(t *testing.T) {
	t.Parallel()
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	require.NoError(t, err)
	peerKey, err := curve.GenerateKey(rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name            string
		privKey         []byte
		privType        KEYTYPE
		pubKey          []byte
		pubType         KEYTYPE
		wantErrContains string
	}{
		{
			name:     "valid-x25519",
			privKey:  privKey.Bytes(),
			privType: KEYTYPE_X25519,
			pubKey:   peerKey.PublicKey().Bytes(),
			pubType:  KEYTYPE_X25519,
		},
		{
			name:            "mismatched-types",
			privKey:         privKey.Bytes(),
			privType:        KEYTYPE_X25519,
			pubKey:          peerKey.PublicKey().Bytes(),
			pubType:         KEYTYPE_MLKEM1024,
			wantErrContains: "key types do not match",
		},
		{
			name:            "mlkem-not-supported-yet",
			privKey:         []byte("private"),
			privType:        KEYTYPE_MLKEM1024,
			pubKey:          []byte("public"),
			pubType:         KEYTYPE_MLKEM1024,
			wantErrContains: "invalid private key type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sharedKey, err := DeriveSharedX25519EncryptionKey(tt.privKey, tt.privType, tt.pubKey, tt.pubType)
			if tt.wantErrContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContains)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, sharedKey)
		})
	}
}
