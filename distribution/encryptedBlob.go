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
	"net/url"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/pkg/errors"
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
	*EnCrypto `json:"crypto"`
}

func (eb *encryptedBlobNew) DecryptBlob(opts *crypto.Opts, outname string) (DecryptedBlob, error) {
	kb, err := eb.DecryptKey(opts)
	if err != nil {
		return nil, err
	}
	return kb.DecryptFile(outname)
}

func (eb *encryptedBlobNew) DecryptKey(opts *crypto.Opts) (KeyDecryptedBlob, error) {
	dk, err := DecryptKey(*eb.EnCrypto, opts)
	if err != nil {
		return nil, errors.WithStack(err)
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

func (e *encryptedBlobCompat) DecryptBlob(opts *crypto.Opts, outname string) (DecryptedBlob, error) {
	eb, err := compat2New(e)
	if err != nil {
		return nil, err
	}

	return eb.DecryptBlob(opts, outname)
}

func (e *encryptedBlobCompat) DecryptKey(opts *crypto.Opts) (KeyDecryptedBlob, error) {
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
