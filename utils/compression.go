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
	"compress/gzip"
	"io"
	"os"
)

// Compress a file as gz, should already be tarred
func Compress(file string) error {
	out, err := os.Create(file + ".gz")
	defer out.Close()

	if err != nil {
		return err
	}

	w := gzip.NewWriter(out)
	defer w.Close()

	in, err := os.Open(file)
	if err != nil {
		return err
	}
	defer in.Close()

	io.Copy(w, in)

	return nil
}
