package nodee

import (
	"context"
	"fmt"
	"reflect"

	"google.golang.org/protobuf/proto"
)

// Storage is an interface for to store values. The interface operates on
// proto.Message, which is satisifed by all types in this library and provides
// some type safety vs. any. Operations that only require an ID still use a
// message so that the type of the message can be used in implementations to
// e.g. separate storage locations.
type Storage interface {
	// Store stores the message
	Store(context.Context, MessageWithId) error

	// Load loads values into the given message. The message must be populated
	// with the ID value. If not found, the returned error should be
	// ErrNotFound.
	Load(context.Context, MessageWithId) error

	// Remove removes the given message. Only the ID field of the message is
	// considered.
	Remove(context.Context, MessageWithId) error

	// List returns a list of IDs; the type of the message is used to
	// disambiguate what to list.
	List(context.Context, proto.Message) ([]string, error)
}

// MessageWithId is a proto message that is required to implement a GetId
// function
type MessageWithId interface {
	proto.Message
	GetId() string
}

// ValidateMsg contains some common functions that can be used to ensure that
// the message is valid before further processing:
//
// * It's not nil
// * It's a pointer
//
// What this doesn't do is tell you whether it's one of the known package types,
// to avoid circular dependencies.
func ValidateMsg(msg MessageWithId) error {
	const op = "nodee.ValidateMsg"
	if msg == nil {
		return fmt.Errorf("(%s) nil message passed in to validate", op)
	}
	if reflect.TypeOf(msg).Kind() != reflect.Pointer {
		return fmt.Errorf("(%s) input message is not a pointer", op)
	}
	return nil
}

// TransactionalStorage is storage that supports transactions. If the underlying
// storage does not support transactions, use NopTransactionStorage() to wrap
// any nodee.Storage implementation.
type TransactionalStorage interface {
	Storage

	// Flush is called when storage is done being performed. The boolean
	// parameter indicates whether the operation was successful (true) or failed
	// (false). Regardless, any error in committing or rolling back the
	// transaction should return an error here, which will cause the library
	// function to return an error as well.
	Flush(bool) error
}

func NopTransactionStorage(storage Storage) TransactionalStorage {
	return &nonTransactionalStorage{Storage: storage}
}

type nonTransactionalStorage struct {
	Storage
}

func (n *nonTransactionalStorage) Flush(_ bool) error {
	return nil
}
