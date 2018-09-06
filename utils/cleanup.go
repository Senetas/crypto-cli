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
	"os"

	"github.com/pkg/errors"
)

// RemoveFunc is the function to remove dir
var RemoveFunc = os.RemoveAll

// CleanUp temporary files
func CleanUp(dir string, err error) error {
	if dir == "" {
		return err
	}
	if err2 := RemoveFunc(dir); err2 != nil {
		if err != nil {
			err2 = errors.Wrapf(err, err2.Error())
		}
		err = errors.Wrapf(err2, "could not clean up temp files in: %s", dir)
	}
	return err
}
