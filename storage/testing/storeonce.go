// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testing

import (
	"context"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/storage/inmem"
	"github.com/hashicorp/nodeenrollment/types"
)

// StoreOnce is an in-memory storage that does not overrwite information on store
type Storage struct {
	*inmem.Storage
}

// New creates a new object that implements the Storage interface in memory. It
// is thread-safe.
func New(ctx context.Context) (*Storage, error) {
	store, err := inmem.New(ctx)
	if err != nil {
		return nil, err
	}
	return &Storage{
		store,
	}, nil
}

// Store implements the Storage interface.
//
// If the message already exists, return a duplicate record error
func (ts *Storage) Store(ctx context.Context, msg nodeenrollment.MessageWithId) error {
	const op = "nodeenrollment.storage.inmem.storeonce.(Storage).Store"
	switch msg.(type) {
	case *types.NodeInformation:
		loadNode := types.NodeInformation{Id: msg.GetId()}
		err := ts.Load(ctx, &loadNode)
		if err == nil {
			return types.DuplicateRecordError{}
		}
	case *types.RootCertificates:
		loadRoot := types.RootCertificate{Id: msg.GetId()}
		err := ts.Load(ctx, &loadRoot)
		if err == nil {
			return types.DuplicateRecordError{}
		}
	}

	return ts.Storage.Store(ctx, msg)
}
