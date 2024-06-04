// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package testing

import (
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/storage/inmem"
	"github.com/hashicorp/nodeenrollment/types"
)

var _ nodeenrollment.NodeIdLoader = (*Storage)(nil)

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
			// Randomize what form of dupe record error we return
			s1 := rand.NewSource(time.Now().UnixNano())
			r1 := rand.New(s1)
			num := r1.Intn(2)
			if num == 0 {
				return new(types.DuplicateRecordError)
			}
			return types.DuplicateRecordError{}
		}
	case *types.RootCertificates:
		loadRoot := types.RootCertificate{Id: msg.GetId()}
		err := ts.Load(ctx, &loadRoot)
		if err == nil {
			// Randomize what form of dupe record error we return
			s1 := rand.NewSource(time.Now().UnixNano())
			r1 := rand.New(s1)
			num := r1.Intn(2)
			if num == 0 {
				return new(types.DuplicateRecordError)
			}
			return types.DuplicateRecordError{}
		}
	}

	return ts.Storage.Store(ctx, msg)
}

// LoadByNodeId implements the NodeIdLoader interface. Iterate through all NodeInformation records
// and return those matching the NodeId
func (ts *Storage) LoadByNodeId(ctx context.Context, msg nodeenrollment.MessageWithNodeId) error {
	if msg.GetNodeId() == "" {
		return errors.New("nodeID is required")
	}

	switch t := msg.(type) {
	case *types.NodeInformations:
		nodes, err := ts.Storage.List(ctx, (*types.NodeInformation)(nil))
		if err != nil {
			return err
		}

		nodesToReturn := make([]*types.NodeInformation, 0)
		for _, n := range nodes {
			node := &types.NodeInformation{Id: n}
			ts.Load(ctx, node)
			if node.NodeId == msg.GetNodeId() {
				nodesToReturn = append(nodesToReturn, node)
			}
		}
		if len(nodesToReturn) == 0 {
			return nodeenrollment.ErrNotFound
		}
		t.Nodes = nodesToReturn
	}
	return nil
}
