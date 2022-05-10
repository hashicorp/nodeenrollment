package nodee

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// SubjectKeyInfoAndKeyIdFromPubKey returns the PKIX-encoded public key and the
// library-specific key ID derived from it
func SubjectKeyInfoAndKeyIdFromPubKey(pubKey any) ([]byte, string, error) {
	const op = "nodee.SubjectKeyInfoAndKeyIdFromPubKey"
	pubKeyPkix, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, "", fmt.Errorf("(%s) error marshaling public key: %w", op, err)
	}
	return pubKeyPkix, KeyIdFromPkix(pubKeyPkix), nil
}

// KeyIdFromPkix derives the library-specific key ID from the PKIX-encoed public
// key
func KeyIdFromPkix(pkixKey []byte) string {
	shaPubKey := sha256.Sum256(pkixKey)
	return hex.EncodeToString(shaPubKey[0:16])
}
