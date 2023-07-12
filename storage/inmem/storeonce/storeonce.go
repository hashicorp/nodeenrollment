// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package storeonce

import (
	"context"
	"fmt"

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

	if err := types.ValidateMessage(msg); err != nil {
		return fmt.Errorf("(%s) given message cannot be stored: %w", op, err)
	}
	subPath, err := inmem.SubPathFromMsg(msg)
	if err != nil {
		return fmt.Errorf("(%s) given message cannot be stored: %w", op, err)
	}
	return ts.StoreValue(ctx, msg.GetId(), subPath, msg)
}
