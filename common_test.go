package nodeenrollment

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestIsNil(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   any
		want bool
	}{
		{
			name: "nil outside",
			in:   nil,
			want: true,
		},
		{
			name: "nil interface type",
			in:   proto.Message(nil),
			want: true,
		},
		{
			name: "non pointer",
			in:   struct{}{},
			want: false,
		},
		{
			name: "pointer",
			in:   &struct{}{},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsNil(tt.in))
		})
	}
}
