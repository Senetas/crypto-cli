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

	digest "github.com/opencontainers/go-digest"
)

// Compress a file as gz, should already be tarred
func Compress(file string) (err error) {
	out, err := os.Create(file + ".gz")
	defer func() {
		err = CheckedClose(out, err)
	}()

	w := gzip.NewWriter(out)
	defer func() {
		err = CheckedClose(w, err)
	}()

	in, err := os.Open(file)
	if err != nil {
		return err
	}
	defer func() {
		err = CheckedClose(in, err)
	}()

	io.Copy(w, in)

	return nil
}

// Decompress a file as gz, should already be tarred
func Decompress(file string) (d *digest.Digest, err error) {
	out, err := os.Create(file + ".dec")
	if err != nil {
		return nil, err
	}
	defer func() {
		err = CheckedClose(out, err)
	}()

	in, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = CheckedClose(in, err)
	}()

	r, err := gzip.NewReader(in)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = CheckedClose(r, err)
	}()

	pr, pw := io.Pipe()
	tr := io.TeeReader(r, pw)
	digester := digest.Canonical.Digester()

	done := make(chan int64)
	defer close(done)
	errChan := make(chan error)
	defer close(errChan)

	go func() {
		var err2 error
		defer func() {
			err2 = pw.Close()
		}()

		n, err2 := io.Copy(out, tr)

		errChan <- err2
		done <- n
	}()

	go func() {
		n, err2 := io.Copy(digester.Hash(), pr)
		errChan <- err2
		done <- n
	}()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			return nil, err
		}
		<-done
	}

	ds := digester.Digest()
	return &ds, nil
}
