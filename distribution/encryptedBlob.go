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
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/crypto"
)

// EncryptedBlob is a blob that may be decrypted
type EncryptedBlob interface {
	Blob
	// DecryptBlob decrypts:
	//     The Key encryption key contained in the "EnCrypto" struct
	//     The data stream in the FileHandle io.Reader
	// The data is also decompressed and written to a file which is referenced
	// in the "Filename"
	DecryptBlob(opts *crypto.Opts, outfile string) (DecryptedBlob, error)
	DecryptKey(opts *crypto.Opts) (KeyDecryptedBlob, error)
}

// EncryptedBlob is the go type for an encrypted element in the layer array
type encryptedBlobNew struct {
	*NoncryptedBlob
	*crypto.EnCrypto `json:"crypto"`
}

func (eb *encryptedBlobNew) DecryptBlob(opts *crypto.Opts, outname string) (_ DecryptedBlob, err error) {
	kb, err := eb.DecryptKey(opts)
	if err != nil {
		return
	}
	return kb.DecryptFile(opts, outname)
}

func (eb *encryptedBlobNew) DecryptKey(opts *crypto.Opts) (_ KeyDecryptedBlob, err error) {
	dk, err := crypto.DecryptKey(*eb.EnCrypto, opts)
	if err != nil {
		return
	}
	return &keyDecryptedBlob{
		NoncryptedBlob: eb.NoncryptedBlob,
		DeCrypto:       &dk,
	}, nil
}

// EncryptedBlob is the go type for an encrypted element in the layer array
type encryptedBlobCompat struct {
	*NoncryptedBlob
	URLs []string `json:"urls"`
}

func (e *encryptedBlobCompat) DecryptBlob(opts *crypto.Opts, outname string) (_ DecryptedBlob, err error) {
	ek, err := crypto.NewEncryptoCompat(e.URLs, opts)
	if err != nil {
		return
	}

	eb := &encryptedBlobNew{
		NoncryptedBlob: e.NoncryptedBlob,
		EnCrypto:       &ek,
	}

	return eb.DecryptBlob(opts, outname)
}

func (e *encryptedBlobCompat) DecryptKey(opts *crypto.Opts) (_ KeyDecryptedBlob, err error) {
	ek, err := crypto.NewEncryptoCompat(e.URLs, opts)
	if err != nil {
		return
	}

	dk, err := crypto.DecryptKey(ek, opts)
	if err != nil {
		return
	}

	return &keyDecryptedBlob{
		NoncryptedBlob: e.NoncryptedBlob,
		DeCrypto:       &dk,
	}, nil
}

type encryptedConfigNew struct {
	*NoncryptedBlob
	*crypto.EnCrypto `json:"crypto"`
}

func (ec *encryptedConfigNew) DecryptBlob(opts *crypto.Opts, outname string) (_ DecryptedBlob, err error) {
	kc, err := ec.DecryptKey(opts)
	if err != nil {
		return
	}
	return kc.DecryptFile(opts, outname)
}

func (ec *encryptedConfigNew) DecryptKey(opts *crypto.Opts) (_ KeyDecryptedBlob, err error) {
	dk, err := crypto.DecryptKey(*ec.EnCrypto, opts)
	if err != nil {
		return
	}
	return &keyDecryptedConfig{
		NoncryptedBlob: ec.NoncryptedBlob,
		DeCrypto:       &dk,
	}, nil
}

type encryptedConfigCompat struct {
	*NoncryptedBlob
	URLs []string `json:"urls"`
}

func (e *encryptedConfigCompat) DecryptBlob(opts *crypto.Opts, outname string) (_ DecryptedBlob, err error) {
	ek, err := crypto.NewEncryptoCompat(e.URLs, opts)
	if err != nil {
		return
	}

	eb := &encryptedConfigNew{
		NoncryptedBlob: e.NoncryptedBlob,
		EnCrypto:       &ek,
	}

	return eb.DecryptBlob(opts, outname)
}

func (e *encryptedConfigCompat) DecryptKey(opts *crypto.Opts) (_ KeyDecryptedBlob, err error) {
	ek, err := crypto.NewEncryptoCompat(e.URLs, opts)
	if err != nil {
		return
	}

	dk, err := crypto.DecryptKey(ek, opts)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	return &keyDecryptedConfig{
		NoncryptedBlob: e.NoncryptedBlob,
		DeCrypto:       &dk,
	}, nil
}
