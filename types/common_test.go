package types

import (
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
			msg:  new(RootCertificate),
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
