// Copyright © 2018 SENETAS SECURITY PTY LTD
//
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

package utils

import "bytes"

var (
	// ErrDecrypt return this when any error occurs in the decryption process
	ErrDecrypt = NewError("could not decrypt", false)
	// ErrEncrypt return this when any error occurs in the encryption process
	ErrEncrypt = NewError("could not encrypt", false)
)

// Error is an error type that may be used to turn off the stack trace
type Error struct {
	errtext  string
	HasStack bool
}

// StripTrace cause the stack trace to not print on the error
// Not that it evaluates the Error() function
func StripTrace(e error) error {
	return WrapError(e, false)
}

// NewError creates a new Error
func NewError(errtext string, hasStack bool) Error {
	return Error{errtext, hasStack}
}

// WrapError creates a new Error
func WrapError(err error, hasStack bool) Error {
	return Error{err.Error(), hasStack}
}

func (e Error) Error() string {
	return e.errtext
}

// Errors holds mutiple errors
type Errors []error

func (es Errors) Error() string {
	if len(es) == 0 {
		return ""
	} else if len(es) == 1 {
		return es[0].Error()
	}

	i := 0
	for ; i < len(es) && es[i] == nil; i++ {
	}

	var msg *bytes.Buffer
	if i < len(es) {
		msg = bytes.NewBufferString(es[i].Error())
	}

	for j := i + 1; j < len(es); j++ {
		if _, err := msg.WriteString("\n"); err != nil {
			return "buffer became too large"
		}
		if _, err := msg.WriteString(es[j].Error()); err != nil {
			return "buffer became too large"
		}
	}

	return msg.String()
}

// ConcatErrChan concatenates all the errors in the channel into in a single error
func ConcatErrChan(errChan <-chan error, expected int) error {
	var errs Errors
	for i := 0; i < expected; i++ {
		if err := <-errChan; err != nil {
			errs = append(errs, err)
		}
	}

	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	}

	return errs
}
