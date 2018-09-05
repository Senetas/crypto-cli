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

import "errors"

// Uint64ToPosInt convertes a uint64 to an int if it is positive as an int, returning an error
// otherwise
func Uint64ToPosInt(i uint64) (o int, err error) {
	o = int(i)
	if o < 0 {
		err = errors.New("expected positive integer")
	}
	return
}
