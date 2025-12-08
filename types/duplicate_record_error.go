// Copyright IBM Corp. 2022, 2025
// SPDX-License-Identifier: MPL-2.0

package types

const dupeRecordErr = "duplicate record found"

type DuplicateRecordError struct {
}

func (d DuplicateRecordError) Error() string {
	return dupeRecordErr
}
