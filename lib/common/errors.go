// Copyright (c) 2016 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import "fmt"

// Error indicating a problem connecting to the backend.
type ErrorDatastoreError struct {
	Err error
}

func (e ErrorDatastoreError) Error() string {
	return e.Err.Error()
}

// Error indicating a resource does not exist.  Used when attempting to delete or
// udpate a non-existent resource.
type ErrorResourceDoesNotExist struct {
	Err  error
	Name string
}

func (e ErrorResourceDoesNotExist) Error() string {
	return fmt.Sprintf("resource does not exists with name '%s'", e.Name)
}

// Error indicating a resource already exists.  Used when attempting to create a
// resource that already exists.
type ErrorResourceAlreadyExists struct {
	Err  error
	Name string
}

func (e ErrorResourceAlreadyExists) Error() string {
	return fmt.Sprintf("resource already exists with name '%s'", e.Name)
}

// Error indicating a problem connecting to the backend.
type ErrorConnectionUnauthorized struct {
	Err error
}

func (e ErrorConnectionUnauthorized) Error() string {
	return "connection is unauthorized"
}

// Validation error containing the fields that are failed validation.
type ErrorValidation struct {
	ErrFields []ErroredField
}

type ErroredField struct {
	Name  string
	Value interface{}
}

func (e ErrorValidation) Error() string {
	if len(e.ErrFields) == 0 {
		return "unknown validation error"
	} else if len(e.ErrFields) == 1 {
		return fmt.Sprintf("error with field %s = '%v'",
			e.ErrFields[0].Name,
			e.ErrFields[0].Value)
	} else {
		s := "error with the following fields:\n"
		for _, f := range e.ErrFields {
			s = s + fmt.Sprintf("-  %s = '%v'\n",
				f.Name,
				f.Value)
		}
		return s
	}
}

type ErrorInsufficientIdentifiers struct {
}

func (e ErrorInsufficientIdentifiers) Error() string {
	return "insufficient identifiers"
}
