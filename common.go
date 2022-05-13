package nodeenrollment

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/sethvargo/go-diceware/diceware"
)

// SubjectKeyInfoAndKeyIdFromPubKey returns the PKIX-encoded public key and the
// library-specific key ID derived from it
func SubjectKeyInfoAndKeyIdFromPubKey(pubKey any) ([]byte, string, error) {
	const op = "nodeenrollment.SubjectKeyInfoAndKeyIdFromPubKey"
	pubKeyPkix, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, "", fmt.Errorf("(%s) error marshaling public key: %w", op, err)
	}
	keyId, err := KeyIdFromPkix(pubKeyPkix)
	if err != nil {
		return nil, "", fmt.Errorf("(%s) error getting key id: %w", op, err)
	}
	return pubKeyPkix, keyId, nil
}

// KeyIdFromPkix derives the library-specific key ID from the PKIX-encoed public
// key
func KeyIdFromPkix(pkixKey []byte) (string, error) {
	const op = "nodeenrollment.KeyIdFromPkix"
	shaPubKey := sha256.Sum256(pkixKey)
	// This never returns a non-nil error (nor is there reason for it to), so
	// ignore
	gen, _ := diceware.NewGenerator(&diceware.GeneratorInput{RandReader: bytes.NewReader(shaPubKey[:])})
	words, err := gen.Generate(KeyIdNumWords)
	if err != nil {
		return "", fmt.Errorf("(%s) error generating key id: %w", op, err)
	}
	return strings.Join(words, "-"), nil
}
