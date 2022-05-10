package nodee

import (
	"errors"
	"time"
)

const (
	DefaultDuration                   = time.Hour * 24 * 14 // two weeks
	CommonDnsName                     = "pay-no-attention-to-that-pers-on-behind-the-curt-on"
	FetchNodeCredsNextProtoV1Prefix   = "v1-nodee-fetch-node-creds"
	AuthenticateNodeNextProtoV1Prefix = "v1-nodee-authenticate-node-"
	CurrentId                         = "current"
	NextId                            = "next"
	NonceSize                         = 32
)

var ErrNotFound = errors.New("not found")
