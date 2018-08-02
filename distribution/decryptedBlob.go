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
	EncryptBlob(opts crypto.Opts, outfile string) (EncryptedBlob, error)
}

type decryptedBlob struct {
	*NoncryptedBlob
	*DeCrypto `json:"-"`
}

func (db *decryptedBlob) EncryptBlob(opts crypto.Opts, outname string) (_ EncryptedBlob, err error) {
	r, err := db.ReadCloser()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(r, err) }()

	out, err := os.Create(outname)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(out, err) }()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), out)

	ew, err := crypto.EncBlobWriter(mw, db.DecKey)
	if err != nil {
		return nil, err
	}

	zw := gzip.NewWriter(ew)

	n, err := io.Copy(zw, r)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// the writers must be closed for the data to be written
	if err = zw.Close(); err != nil {
		return nil, errors.WithStack(err)
	}

	if err = ew.Close(); err != nil {
		return nil, errors.WithStack(err)
	}

	dgst := digester.Digest()

	ek, err := EncryptKey(*db.DeCrypto, opts)
	if err != nil {
		return nil, err
	}

	nb := &NoncryptedBlob{
		Size:        n,
		ContentType: db.ContentType,
		Digest:      &dgst,
		Filename:    outname,
	}

	if opts.Compat {
		u, err := url.Parse(BaseCryptoURL)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		v := url.Values{}
		v.Set(AlgosKey, string(ek.Algos))
		v.Set(KeyKey, ek.EncKey)
		u.RawQuery = v.Encode()

		return &encryptedBlobCompat{
			NoncryptedBlob: nb,
			URLs:           []string{u.String()},
		}, nil
	}

	return &encryptedBlobNew{
		NoncryptedBlob: nb,
		EnCrypto:       &ek,
	}, nil
}

type decryptedConfig struct {
	*NoncryptedBlob
	*DeCrypto `json:"-"`
}

func (db *decryptedConfig) EncryptBlob(opts crypto.Opts, outname string) (_ EncryptedBlob, err error) {
	r, err := db.ReadCloser()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(r, err) }()

	out, err := os.Create(outname)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(out, err) }()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), out)

	dc := &decConfig{}
	if err = json.NewDecoder(r).Decode(dc); err != nil {
		return nil, err
	}

	ec, err := dc.Encrypt(db.DecKey, opts)
	if err != nil {
		return nil, err
	}

	cw := &utils.CounterWriter{Writer: mw}

	if err = json.NewEncoder(cw).Encode(ec); err != nil {
		return nil, err
	}

	dgst := digester.Digest()

	nb := &NoncryptedBlob{
		Size:        int64(cw.Count),
		ContentType: db.ContentType,
		Digest:      &dgst,
		Filename:    outname,
	}

	ek, err := EncryptKey(*db.DeCrypto, opts)
	if err != nil {
		return nil, err
	}

	if opts.Compat {
		u, err := url.Parse(BaseCryptoURL)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		v := url.Values{}
		v.Set(AlgosKey, string(ek.Algos))
		v.Set(KeyKey, ek.EncKey)
		u.RawQuery = v.Encode()

		return &encryptedConfigCompat{
			NoncryptedBlob: nb,
			URLs:           []string{u.String()},
		}, nil
	}

	return &encryptedConfigNew{
		NoncryptedBlob: nb,
		EnCrypto:       &ek,
	}, nil
}
