// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

const dupeRecordErr = "duplicate NodeInformation record found"

type DuplicateRecordError struct {
}

func (d DuplicateRecordError) Error() string {
	return dupeRecordErr
}
