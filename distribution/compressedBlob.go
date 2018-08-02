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

package distribution

import (
	"compress/gzip"
	"io"
	"os"

	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/utils"
)

// CompressedBlob is a blob that may be decompressed
type CompressedBlob interface {
	Blob
	Decompress(outfile string) (DecompressedBlob, error)
}

// DecompressedBlob is a blob that may be compressed
type DecompressedBlob interface {
	Blob
	Compress(outfile string) (CompressedBlob, error)
}

// Decompress decompresses a blob
func (b *NoncryptedBlob) Decompress(outfile string) (_ DecompressedBlob, err error) {
	r, err := b.ReadCloser()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(r, err) }()

	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(zr, err) }()

	out, err := os.Create(outfile)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(out, err) }()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), out)

	size, err := io.Copy(mw, zr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	dgst := digester.Digest()

	return &NoncryptedBlob{
		Size:        size,
		ContentType: b.ContentType,
		Digest:      &dgst,
		Filename:    outfile,
	}, nil
}

// Compress compresses a blob
func (b *NoncryptedBlob) Compress(outfile string) (_ CompressedBlob, err error) {
	r, err := b.ReadCloser()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(r, err) }()

	out, err := os.Create(outfile)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(out, err) }()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), out)
	zw := gzip.NewWriter(mw)

	size, err := io.Copy(zw, r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if err := zw.Close(); err != nil {
		return nil, errors.WithStack(err)
	}

	dgst := digester.Digest()

	return &NoncryptedBlob{
		Size:        size,
		ContentType: b.ContentType,
		Digest:      &dgst,
		Filename:    outfile,
	}, nil
}
