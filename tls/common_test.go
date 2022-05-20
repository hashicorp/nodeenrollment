package tls

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNextProtos(t *testing.T) {
	t.Parallel()

	const prefix = "nextprotos-testing"

	tests := []struct {
		name           string
		value          string
		expectedChunks int
		prefixOverride string
	}{
		{
			name:           "short",
			value:          "foo",
			expectedChunks: 1,
		},
		{
			name:           "long",
			value:          strings.Repeat("foo", 300),
			expectedChunks: 5,
		},
		{
			name:           "long-prefix-override",
			value:          strings.Repeat("foo", 300),
			expectedChunks: 5,
			prefixOverride: "nextprotos-prefixoveride",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			chunks := BreakIntoNextProtos(prefix, tt.value)
			assert.Len(chunks, tt.expectedChunks)
			for _, chunk := range chunks {
				assert.True(strings.HasPrefix(chunk, prefix))
			}

			combinePrefix := prefix
			if tt.prefixOverride != "" {
				combinePrefix = tt.prefixOverride
			}

			recon := CombineFromNextProtos(combinePrefix, chunks)
			if tt.prefixOverride == "" {
				assert.False(strings.HasPrefix(recon, prefix))
				assert.Equal(tt.value, recon)
			} else {
				assert.Empty(recon)
			}
		})
	}
}
