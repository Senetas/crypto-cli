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
	"github.com/pkg/errors"
)

// Compress a file as gz, should already be tarred
// assumes file uses the system seperator
func Compress(file string) (err error) {
	in, err := os.Open(file)
	if err != nil {
		return errors.Wrapf(err, "could not open: %s", file)
	}
	defer func() { err = CheckedClose(in, err) }()

	out, err := os.Create(file + ".gz")
	if err != nil {
		return errors.Wrapf(err, "could not create: %s.gz", file)
	}
	defer func() { err = CheckedClose(out, err) }()

	w := gzip.NewWriter(out)
	defer func() { err = CheckedClose(w, err) }()

	if _, err = io.Copy(w, in); err != nil {
		return errors.Wrapf(err, "error compressing %s to %s.gz", file, file)
	}

	return nil
}

// CompressWithDigest a file as gz, should already be tarred
// assumes file uses the system seperator
func CompressWithDigest(file string) (d *digest.Digest, err error) {
	in, err := os.Open(file)
	if err != nil {
		return nil, errors.Wrapf(err, "could not open: %s", file)
	}
	defer func() { err = CheckedClose(in, err) }()

	out, err := os.Create(file + ".gz")
	if err != nil {
		return nil, errors.Wrapf(err, "could not create: %s.gz", file)
	}
	defer func() { err = CheckedClose(out, err) }()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), out)
	zw := gzip.NewWriter(mw)

	if _, err = io.Copy(zw, in); err != nil {
		return nil, errors.Wrapf(err, "error decompressing %s.gz to %s", file, file)
	}

	if err = zw.Close(); err != nil {
		return nil, err
	}

	ds := digester.Digest()
	return &ds, nil
}

// Decompress a file as gz, should already be tarred, assumes file uses the
// system seperator (i.e. built with filepath). Also calcuates the digest in parallel
func Decompress(file string) (d *digest.Digest, err error) {
	in, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer func() { err = CheckedClose(in, err) }()

	out, err := os.Create(file + ".dec")
	if err != nil {
		return nil, err
	}
	defer func() { err = CheckedClose(out, err) }()

	zr, err := gzip.NewReader(in)
	if err != nil {
		return nil, err
	}

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), out)

	if _, err = io.Copy(mw, zr); err != nil {
		return nil, err
	}

	if err = zr.Close(); err != nil {
		return nil, err
	}

	ds := digester.Digest()
	return &ds, nil
}
