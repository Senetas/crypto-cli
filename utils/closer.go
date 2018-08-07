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

import "io"

// CheckedClose may be called on defer to properly close a resource and log any errors
func CheckedClose(c io.Closer, err error) error {
	if c == nil {
		return err
	}

	if err2 := c.Close(); err2 != nil {
		if err != nil {
			return Errors{err, err2}
		}
		return err2
	}

	return err
}
