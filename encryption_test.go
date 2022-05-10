package nodee_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	nodee "github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/noderegistration"
	"github.com/hashicorp/nodeenrollment/nodestorage/file"
	"github.com/hashicorp/nodeenrollment/nodetesting"
	"github.com/hashicorp/nodeenrollment/nodetypes"
	"github.com/hashicorp/nodeenrollment/rotation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func Test_EncryptionDecryption(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storage, err := file.NewFileStorage(ctx)
	require.NoError(t, err)
	t.Cleanup(storage.Cleanup)

	wrapper := nodetesting.TestWrapper(t)

	_, err = rotation.RotateRootCertificates(ctx, storage)
	require.NoError(t, err)

	node1, err := noderegistration.RegisterViaOperatorLedFlow(ctx, storage, &nodetypes.OperatorLedRegistrationRequest{})
	require.NoError(t, err)

	node2, err := noderegistration.RegisterViaOperatorLedFlow(ctx, storage, &nodetypes.OperatorLedRegistrationRequest{})
	require.NoError(t, err)

	tests := []struct {
		name               string
		nodeCreds          *nodetypes.NodeCredentials
		otherNodeCreds     *nodetypes.NodeCredentials
		encryptId          string
		decryptId          string
		encryptMsg         proto.Message
		decryptMsg         proto.Message
		encryptKeySource   nodee.X25519Producer
		decryptKeySource   nodee.X25519Producer
		encDecWrapper      wrapping.Wrapper
		wantErrContains    string
		wantEncErrContains string
		wantDecErrContains string
	}{
		{
			name:             "valid",
			nodeCreds:        node1,
			encryptId:        "foo",
			decryptId:        "foo",
			encryptMsg:       node1,
			decryptMsg:       new(nodetypes.NodeCredentials),
			encryptKeySource: node1,
			decryptKeySource: node1,
		},
		{
			name:             "valid-with-wrapper",
			nodeCreds:        node1,
			encryptId:        "foo",
			decryptId:        "foo",
			encryptMsg:       node1,
			decryptMsg:       new(nodetypes.NodeCredentials),
			encryptKeySource: node1,
			decryptKeySource: node1,
			encDecWrapper:    wrapper,
		},
		{
			name:               "mismatched-id",
			nodeCreds:          node1,
			encryptId:          "foo",
			decryptId:          "bar",
			encryptMsg:         node1,
			decryptMsg:         new(nodetypes.NodeCredentials),
			encryptKeySource:   node1,
			decryptKeySource:   node1,
			wantDecErrContains: "message authentication failed",
		},
		{
			name:               "empty-encrypt-msg",
			nodeCreds:          node1,
			encryptId:          "foo",
			decryptId:          "bar",
			encryptMsg:         nil,
			decryptMsg:         new(nodetypes.NodeCredentials),
			encryptKeySource:   node1,
			decryptKeySource:   node1,
			wantEncErrContains: "incoming message is nil",
		},
		{
			name:               "empty-decrypt-msg",
			nodeCreds:          node1,
			encryptId:          "foo",
			decryptId:          "bar",
			encryptMsg:         node1,
			decryptMsg:         nil,
			encryptKeySource:   node1,
			decryptKeySource:   node1,
			wantDecErrContains: "incoming result message is nil",
		},
		{
			name:               "empty-encrypt-keyproducer",
			nodeCreds:          node1,
			encryptId:          "foo",
			decryptId:          "bar",
			encryptMsg:         node1,
			decryptMsg:         new(nodetypes.NodeCredentials),
			encryptKeySource:   nil,
			decryptKeySource:   node1,
			wantEncErrContains: "incoming key source is nil",
		},
		{
			name:               "empty-decrypt-keyproducer",
			nodeCreds:          node1,
			encryptId:          "foo",
			decryptId:          "bar",
			encryptMsg:         node1,
			decryptMsg:         new(nodetypes.NodeCredentials),
			encryptKeySource:   node1,
			decryptKeySource:   nil,
			wantDecErrContains: "incoming key source is nil",
		},
		{
			name:             "ensure-different-keys",
			nodeCreds:        node1,
			otherNodeCreds:   node2,
			encryptId:        "foo",
			decryptId:        "foo",
			encryptKeySource: node1,
			decryptKeySource: node1,
			wantErrContains:  "unknown type",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			sharedKeyFromNodeCreds, err := tt.nodeCreds.X25519EncryptionKey()
			require.NoError(err)

			nodeInformation, err := nodetypes.LoadNodeInformation(ctx, storage, nodee.KeyIdFromPkix(tt.nodeCreds.CertificatePublicKeyPkix))
			require.NoError(err)
			sharedKeyFromNodeInfo, err := nodeInformation.X25519EncryptionKey()
			require.NoError(err)

			assert.Equal(sharedKeyFromNodeInfo, sharedKeyFromNodeCreds)

			var otherNodeInformation *nodetypes.NodeInformation
			if tt.otherNodeCreds != nil {
				otherNodeInformation, err = nodetypes.LoadNodeInformation(ctx, storage, nodee.KeyIdFromPkix(tt.otherNodeCreds.CertificatePublicKeyPkix))
				require.NoError(err)

				sharedKeyFromOtherNodeInfo, err := otherNodeInformation.X25519EncryptionKey()
				require.NoError(err)

				assert.NotEqual(sharedKeyFromNodeInfo, sharedKeyFromOtherNodeInfo)
				return
			}

			ct, err := nodee.EncryptMessage(ctx, tt.encryptId, tt.encryptMsg, tt.encryptKeySource, nodee.WithWrapper(tt.encDecWrapper))
			if tt.wantEncErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantEncErrContains)
				return
			}
			require.NoError(err)
			err = nodee.DecryptMessage(ctx, tt.decryptId, ct, tt.decryptKeySource, tt.decryptMsg, nodee.WithWrapper(tt.encDecWrapper))
			if tt.wantDecErrContains != "" {
				require.Error(err)
				assert.Contains(err.Error(), tt.wantDecErrContains)
				return
			}
			require.NoError(err)
			assert.Empty(cmp.Diff(tt.encryptMsg, tt.decryptMsg, protocmp.Transform()))
		})
	}
}
