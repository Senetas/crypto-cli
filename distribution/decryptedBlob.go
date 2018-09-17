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
	"encoding/json"
	"io"
	"net/url"

	"os"

	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/utils"
)

// DecryptedBlob is a blob that may be encrypted
type DecryptedBlob interface {
	Blob
	// EncryptBlob compresses the blob file and encryptes
	//     The Key encryption key contained in the "DeCrypto" struct
	//     The data stream in the FileHandle io.Reader
	EncryptBlob(opts *crypto.Opts, outfile string) (EncryptedBlob, error)
}

type decryptedBlob struct {
	*NoncryptedBlob
	*crypto.DeCrypto `json:"-"`
}

func (db *decryptedBlob) EncryptBlob(opts *crypto.Opts, outname string) (eb EncryptedBlob, err error) {
	r, err := db.ReadCloser()
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	defer func() { err = utils.CheckedClose(r, err) }()

	out, err := os.Create(outname)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	defer func() { err = utils.CheckedClose(out, err) }()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), out)
	cw := &utils.CounterWriter{Writer: mw}

	ew, err := crypto.EncBlobWriter(cw, db.DecKey)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	zw := gzip.NewWriter(ew)

	if _, err = io.Copy(zw, r); err != nil {
		err = errors.WithStack(err)
		return
	}

	// the writers must be closed for the data to be written
	if err = zw.Close(); err != nil {
		err = errors.WithStack(err)
		return
	}

	if err = ew.Close(); err != nil {
		err = errors.WithStack(err)
		return
	}

	dgst := digester.Digest()

	ek, err := crypto.EncryptKey(*db.DeCrypto, opts)
	if err != nil {
		return
	}

	nb := &NoncryptedBlob{
		Size:        int64(cw.Count),
		ContentType: db.ContentType,
		Digest:      dgst,
		Filename:    outname,
	}

	if opts.Compat {
		var u *url.URL
		u, err = crypto.NewURLCompat(&ek, opts)
		eb = &encryptedBlobCompat{
			NoncryptedBlob: nb,
			URLs:           []string{u.String()},
		}
	} else {
		eb = &encryptedBlobNew{
			NoncryptedBlob: nb,
			EnCrypto:       &ek,
		}
	}
	return
}

type decryptedConfig struct {
	*NoncryptedBlob
	*crypto.DeCrypto `json:"-"`
}

func (db *decryptedConfig) EncryptBlob(opts *crypto.Opts, outname string) (eb EncryptedBlob, err error) {
	r, err := db.ReadCloser()
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	defer func() { err = utils.CheckedClose(r, err) }()

	out, err := os.Create(outname)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	defer func() { err = utils.CheckedClose(out, err) }()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), out)

	dc := &decConfig{}
	if err = json.NewDecoder(r).Decode(dc); err != nil {
		err = errors.WithStack(err)
		return
	}

	ec, err := dc.Encrypt(db.DecKey, db.Nonce, db.Salt)
	if err != nil {
		return
	}

	cw := &utils.CounterWriter{Writer: mw}

	if err = json.NewEncoder(cw).Encode(ec); err != nil {
		err = errors.WithStack(err)
		return
	}

	dgst := digester.Digest()

	nb := &NoncryptedBlob{
		Size:        int64(cw.Count),
		ContentType: db.ContentType,
		Digest:      dgst,
		Filename:    outname,
	}

	ek, err := crypto.EncryptKey(*db.DeCrypto, opts)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	if opts.Compat {
		var u *url.URL
		u, err = crypto.NewURLCompat(&ek, opts)
		eb = &encryptedConfigCompat{
			NoncryptedBlob: nb,
			URLs:           []string{u.String()},
		}
	} else {
		eb = &encryptedConfigNew{
			NoncryptedBlob: nb,
			EnCrypto:       &ek,
		}
	}
	return
}
