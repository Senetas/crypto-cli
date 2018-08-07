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
	"os"
	"path/filepath"

	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/utils"
)

// KeyDecryptedBlob is a type for blobs that have had their key objects
// decrypted but not their files
type KeyDecryptedBlob interface {
	Blob
	DecryptFile(opts *crypto.Opts, outfile string) (DecryptedBlob, error)
	EncryptKey(opts *crypto.Opts) (EncryptedBlob, error)
}

type keyDecryptedBlob struct {
	*NoncryptedBlob
	*DeCrypto `json:"-"`
}

func (kb *keyDecryptedBlob) DecryptFile(opts *crypto.Opts, outfile string) (DecryptedBlob, error) {
	r, err := kb.ReadCloser()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(r, err) }()

	dec, err := crypto.DecBlobReader(r, kb.DeCrypto.DecKey)
	if err != nil {
		return nil, err
	}

	zr, err := gzip.NewReader(dec)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(zr, err) }()

	if err = os.MkdirAll(filepath.Dir(outfile), 0700); err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := os.Create(outfile)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(out, err) }()

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), out)

	n, err := io.Copy(mw, zr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	dgst := digester.Digest()

	return &decryptedBlob{
		NoncryptedBlob: &NoncryptedBlob{
			Size:        n,
			ContentType: kb.ContentType,
			Digest:      dgst,
			Filename:    outfile,
		},
		DeCrypto: kb.DeCrypto,
	}, nil
}

func (kb *keyDecryptedBlob) EncryptKey(opts *crypto.Opts) (EncryptedBlob, error) {
	ek, err := EncryptKey(*kb.DeCrypto, opts)
	if err != nil {
		return nil, err
	}
	return &encryptedBlobNew{
		NoncryptedBlob: kb.NoncryptedBlob,
		EnCrypto:       &ek,
	}, nil
}

type keyDecryptedConfig struct {
	*NoncryptedBlob
	*DeCrypto `json:"-"`
}

func (kc *keyDecryptedConfig) DecryptFile(opts *crypto.Opts, outname string) (DecryptedBlob, error) {
	r, err := kc.ReadCloser()
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

	ec := &encConfig{}
	if err = json.NewDecoder(r).Decode(ec); err != nil {
		return nil, err
	}

	dc, err := ec.Decrypt(kc.DecKey, opts)
	if err != nil {
		return nil, err
	}

	cw := &utils.CounterWriter{Writer: mw}
	nnw := utils.NewNoNewlineWriter(cw)

	if err = json.NewEncoder(nnw).Encode(dc); err != nil {
		return nil, err
	}

	dgst := digester.Digest()

	return &decryptedConfig{
		NoncryptedBlob: &NoncryptedBlob{
			Size:        int64(cw.Count),
			ContentType: kc.ContentType,
			Digest:      dgst,
			Filename:    outname,
		},
		DeCrypto: kc.DeCrypto,
	}, nil
}

func (kc *keyDecryptedConfig) EncryptKey(opts *crypto.Opts) (EncryptedBlob, error) {
	ek, err := EncryptKey(*kc.DeCrypto, opts)
	if err != nil {
		return nil, err
	}
	return &encryptedConfigNew{
		NoncryptedBlob: kc.NoncryptedBlob,
		EnCrypto:       &ek,
	}, nil
}
