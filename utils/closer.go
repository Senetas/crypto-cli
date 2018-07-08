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

import (
	"io"

	"github.com/pkg/errors"
)

// CheckedClose may be called on defer to properly close a resouce and log any errors
func CheckedClose(c io.Closer, err error) error {
	if err2 := c.Close(); err2 != nil {
		return CombineErr([]error{err, err2})
	}
	return err
}

// CombineErr concatenates errors
func CombineErr(es []error) error {
	if len(es) == 0 {
		return nil
	}
	var i int
	var outStr string
	for i = 0; i < len(es) && es[i] == nil; i++ {
	}
	if i < len(es) {
		outStr = es[i].Error()
	}
	for ; i < len(es); i++ {
		if es[i] != nil {
			outStr = outStr + "\n" + es[i].Error()
		}
	}
	return errors.New(outStr)
}
