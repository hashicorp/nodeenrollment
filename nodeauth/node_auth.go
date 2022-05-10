package nodeauth

import (
	"context"

	nodee "github.com/hashicorp/nodeenrollment"
)

// CurrentParameterFactory is a factory function that produces current
// parameters
//
// * Context can be used to give a per-connection context value, or can be
// static.
//
// * Storage is current storage to use. If this implements TransactionalStorage,
// Flush() will be called when appropriate.
//
// * Options are passed through to nodee functions; it is meant for passing the
// current wrapper via WithWrapper specifically
type CurrentParameterFactory func() (
	context.Context,
	nodee.TransactionalStorage,
	[]nodee.Option,
	error,
)

// MadeCurrentParametersFactory is a helper function to make creating
// CurrentParametersFactories easier.
func MakeCurrentParametersFactory(
	ctx context.Context,
	storage nodee.TransactionalStorage,
	opt ...nodee.Option,
) CurrentParameterFactory {
	return func() (
		context.Context,
		nodee.TransactionalStorage,
		[]nodee.Option,
		error,
	) {
		return ctx, storage, opt, nil
	}
}
