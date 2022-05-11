package nodeenrollment

import (
	"context"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/aead"
	"google.golang.org/protobuf/proto"
)

// X25519Producer is an interface that can be satisfied by an underlying type
// that produces an encryption key via X25519.
type X25519Producer interface {
	X25519EncryptionKey() ([]byte, error)
}

// EncryptMessage takes any proto.Message and a valid key source that implements
// X25519Producer. Internally it uses an `aead` wrapper from go-kms-wrapping v2.
// No options are currently supported but in the future non-AES-GCM encryption
// types could be supported by the wrapper and chosen here.
//
// ID is embedded into the wrapped message as the key ID. This can be useful to
// disambiguate either the source or target. It is also passed as additional
// authenticated data to the encryption function, if supported.
//
// The resulting value from the wrapper is marshaled before being returned.
//
// Supported options: WithRandomReader
func EncryptMessage(ctx context.Context, id string, msg proto.Message, keySource X25519Producer, opt ...Option) ([]byte, error) {
	const op = "nodee.EncryptMessage"
	switch {
	case msg == nil:
		return nil, fmt.Errorf("(%s) incoming message is nil", op)
	case keySource == nil:
		return nil, fmt.Errorf("(%s) incoming key source is nil", op)
	}

	opts, err := GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	sharedKey, err := keySource.X25519EncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("(%s) error deriving shared encryption key: %w", op, err)
	}

	aeadWrapper := aead.NewWrapper()
	if _, err := aeadWrapper.SetConfig(
		ctx,
		wrapping.WithKeyId(id),
		aead.WithKey(sharedKey),
		aead.WithRandomReader(opts.WithRandomReader),
	); err != nil {
		return nil, fmt.Errorf("(%s) error instantiating aead wrapper: %w", op, err)
	}

	marshaledMsg, err := proto.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("(%s) error marshaling incoming message: %w", op, err)
	}

	blobInfo, err := aeadWrapper.Encrypt(ctx, marshaledMsg, wrapping.WithAad([]byte(id)))
	if err != nil {
		return nil, fmt.Errorf("(%s) error encrypting marshaled message: %w", op, err)
	}

	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return nil, fmt.Errorf("(%s) error marshaling blob info: %w", op, err)
	}

	return marshaledBlob, nil
}

// DecryptMessage takes any a value encrypted with EncryptMessage and a valid
// key source that implements X25519Producer and decrypts the message into the
// given proto.Message. Internally it uses an `aead` wrapper from
// go-kms-wrapping v2. No options are currently supported but in the future
// non-AES-GCM decryption types could be supported by the wrapper and chosen
// here.
//
// ID should match what was passed into the encryption function. It is also
// passed as additional authenticated data to the decryption function, if
// supported.
func DecryptMessage(ctx context.Context, id string, ct []byte, keySource X25519Producer, result proto.Message, _ ...Option) error {
	const op = "nodee.DecryptMessage"
	switch {
	case len(ct) == 0:
		return fmt.Errorf("(%s) incoming ciphertext is empty", op)
	case keySource == nil:
		return fmt.Errorf("(%s) incoming key source is nil", op)
	case result == nil:
		return fmt.Errorf("(%s) incoming result message is nil", op)
	}

	sharedKey, err := keySource.X25519EncryptionKey()
	if err != nil {
		return fmt.Errorf("(%s) error deriving shared encryption key: %w", op, err)
	}

	aeadWrapper := aead.NewWrapper()
	if _, err := aeadWrapper.SetConfig(
		ctx,
		wrapping.WithKeyId(id),
		aead.WithKey(sharedKey),
	); err != nil {
		return fmt.Errorf("(%s) error instantiating aead wrapper: %w", op, err)
	}

	blobInfo := new(wrapping.BlobInfo)
	if err := proto.Unmarshal(ct, blobInfo); err != nil {
		return fmt.Errorf("(%s) error unmarshaling incoming blob info: %w", op, err)
	}

	pt, err := aeadWrapper.Decrypt(ctx, blobInfo, wrapping.WithAad([]byte(id)))
	if err != nil {
		return fmt.Errorf("(%s) error decrypting blob info: %w", op, err)
	}

	if err := proto.Unmarshal(pt, result); err != nil {
		return fmt.Errorf("(%s) error unmarshaling message into result: %w", op, err)
	}

	return nil
}
