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
	"net/url"
	"os"
	"path/filepath"

	"github.com/minio/sio"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/utils"
)

// encBlobWriter returns an io.WriteCloser that encrypts data with the supplied key
func encBlobWriter(in io.Writer, key []byte) (io.WriteCloser, error) {
	if len(key) != 32 {
		return nil, errors.New("key was of the wrong length")
	}

	cfg := sio.Config{
		MinVersion:   sio.Version20,
		MaxVersion:   sio.Version20,
		CipherSuites: []byte{sio.AES_256_GCM},
		Key:          key,
	}

	out, err := sio.EncryptWriter(in, cfg)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return out, nil
}

// DecFile decrypts (and authenticates) infile and writes it to outfile
// only persists if the decrypttion and authentication suceedes
// assumes infile and outfile use they system seperator
func decBlobReader(in io.Reader, key []byte) (io.Reader, error) {
	if len(key) != 32 {
		return nil, errors.New("key was of the wrong length")
	}

	cfg := sio.Config{
		MinVersion:   sio.Version20,
		MaxVersion:   sio.Version20,
		CipherSuites: []byte{sio.AES_256_GCM},
		Key:          key,
	}

	out, err := sio.DecryptReader(in, cfg)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return out, nil
}

func (eb *encryptedBlobNew) DecryptKey(opts crypto.Opts) (KeyDecryptedBlob, error) {
	dk, err := DecryptKey(*eb.EnCrypto, opts)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &keyDecryptedBlob{
		NoncryptedBlob: eb.NoncryptedBlob,
		DeCrypto:       &dk,
	}, nil
}

func (eb *encryptedBlobNew) DecryptBlob(opts crypto.Opts, outname string) (DecryptedBlob, error) {
	kb, err := eb.DecryptKey(opts)
	if err != nil {
		return nil, err
	}
	return kb.DecryptFile(opts, outname)
}

func (kb *keyDecryptedBlob) EncryptKey(opts crypto.Opts) (EncryptedBlob, error) {
	ek, err := EncryptKey(*kb.DeCrypto, opts)
	if err != nil {
		return nil, err
	}
	return &encryptedBlobNew{
		NoncryptedBlob: kb.NoncryptedBlob,
		EnCrypto:       &ek,
	}, nil
}

func (kb *keyDecryptedBlob) DecryptFile(opts crypto.Opts, outname string) (DecryptedBlob, error) {
	r, err := kb.ReadCloser()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(r, err) }()

	dec, err := decBlobReader(r, kb.DeCrypto.DecKey)
	if err != nil {
		return nil, err
	}

	zr, err := gzip.NewReader(dec)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer func() { err = utils.CheckedClose(zr, err) }()

	if err = os.MkdirAll(filepath.Dir(outname), 0700); err != nil {
		return nil, errors.WithStack(err)
	}

	out, err := os.Create(outname)
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
			Filename:    outname,
			Size:        n,
			ContentType: kb.ContentType,
			Digest:      &dgst,
		},
		DeCrypto: kb.DeCrypto,
	}, nil
}

func (e *encryptedBlobCompat) DecryptKey(opts crypto.Opts) (KeyDecryptedBlob, error) {
	eb, err := compat2New(e)
	if err != nil {
		return nil, err
	}

	dk, err := DecryptKey(*eb.EnCrypto, opts)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &keyDecryptedBlob{
		NoncryptedBlob: eb.NoncryptedBlob,
		DeCrypto:       &dk,
	}, nil
}

func compat2New(e *encryptedBlobCompat) (*encryptedBlobNew, error) {
	if len(e.URLs) == 0 {
		return nil, errors.New("missing encryption key")
	}

	u, err := url.Parse(e.URLs[0])
	if err != nil {
		return nil, errors.WithStack(err)
	}

	algos, err := crypto.ValidateAlgos(u.Query().Get(AlgosKey))
	if err != nil {
		return nil, err
	}

	ek := &EnCrypto{
		Algos:  algos,
		EncKey: u.Query().Get(KeyKey),
	}

	return &encryptedBlobNew{
		NoncryptedBlob: e.NoncryptedBlob,
		EnCrypto:       ek,
	}, nil
}

func (e *encryptedBlobCompat) DecryptBlob(opts crypto.Opts, outname string) (DecryptedBlob, error) {
	eb, err := compat2New(e)
	if err != nil {
		return nil, err
	}

	return eb.DecryptBlob(opts, outname)
}

// EncryptBlob encrypts the key for the layer
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

	ew, err := encBlobWriter(mw, db.DecKey)
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
		Filename:    outname,
		Size:        n,
		ContentType: db.ContentType,
		Digest:      &dgst,
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
		Filename:    outfile,
		Size:        size,
		ContentType: b.ContentType,
		Digest:      &dgst,
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
		Filename:    outfile,
		Size:        size,
		ContentType: b.ContentType,
		Digest:      &dgst,
	}, nil
}
