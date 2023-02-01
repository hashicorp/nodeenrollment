// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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

func TestContainsKnownAlpnProto(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []string
		want bool
	}{
		{
			name: "nil",
			in:   nil,
			want: false,
		},
		{
			name: "single-no-proto",
			in:   []string{"foo"},
			want: false,
		},
		{
			name: "single-fetch-proto",
			in:   []string{FetchNodeCredsNextProtoV1Prefix},
			want: true,
		},
		{
			name: "single-auth-proto",
			in:   []string{AuthenticateNodeNextProtoV1Prefix},
			want: true,
		},
		{
			name: "multi-no-proto",
			in:   []string{"foo", "bar"},
			want: false,
		},
		{
			name: "multi-fetch-proto",
			in:   []string{"foo", FetchNodeCredsNextProtoV1Prefix},
			want: true,
		},
		{
			name: "multi-auth-proto",
			in:   []string{"foo", AuthenticateNodeNextProtoV1Prefix},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ContainsKnownAlpnProto(tt.in...))
		})
	}
}
