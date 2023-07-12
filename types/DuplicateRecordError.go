// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import "fmt"

const dupeRecordErr = "duplicate NodeInformation record found"

type DuplicateRecordError struct {
	NodeInfo *NodeInformation
}

func NewDuplicateRecordError(n *NodeInformation) (DuplicateRecordError, error) {
	const op = "nodeenrollment.types.NewDuplicateRecordError"
	if n == nil {
		return DuplicateRecordError{}, fmt.Errorf("(%s) nil node information", op)
	}
	return DuplicateRecordError{NodeInfo: n}, nil
}

func (d *DuplicateRecordError) Error() string {
	return dupeRecordErr
}

func (d *DuplicateRecordError) GetNodeInformation() *NodeInformation {
	return d.NodeInfo
}
