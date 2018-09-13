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
	"crypto/rand"
	"encoding/base64"
	"net/url"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/utils"
	"github.com/pkg/errors"
)

// SaltIter contains the salt and the number of iterations
type SaltIter struct {
	Salt []byte `json:"-"`
	Iter int    `json:"-"`
}

// EnCrypto is a encrypted key with the algotithms used to encrypt it and the data
type EnCrypto struct {
	Algos  crypto.Algos `json:"cryptoType"`
	EncKey string       `json:"key"`
	SaltIter
}

// NewEncryptoCompat create a new Encrypto struct from some URLs
func NewEncryptoCompat(urls []string, opts *crypto.Opts) (_ *EnCrypto, err error) {
	if len(urls) == 0 {
		err = errors.New("missing encryption key")
		return
	}

	u, err := url.Parse(urls[0])
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	algos, err := crypto.ValidateAlgos(u.Query().Get(AlgosKey))
	if err != nil {
		return
	}

	if algos != opts.EncType {
		err = utils.NewError("encryption type does not match decryption type", false)
		return
	}

	return &EnCrypto{
		Algos:  algos,
		EncKey: u.Query().Get(KeyKey),
	}, nil
}

// DecryptKey is the inverse function of EncryptKey (up to error)
func DecryptKey(e EnCrypto, opts *crypto.Opts) (d DeCrypto, err error) {
	if e.Algos != opts.EncType {
		err = utils.NewError("encryption type does not match decryption type", false)
		return
	}

	decoded, err := base64.URLEncoding.DecodeString(e.EncKey)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	passphrase, err := opts.GetPassphrase(crypto.StdinPassReader)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	d = DeCrypto{Algos: e.Algos}
	d.DecKey, d.Salt, d.Iter, err = crypto.Deckey(decoded, passphrase)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	return
}

// DeCrypto is a decrypted key with the algotithms used to encrypt it and the data
type DeCrypto struct {
	Algos  crypto.Algos `json:"cryptoType"`
	DecKey []byte       `json:"-"`
	SaltIter
}

// NewDecrypto create a new DeCrypto struct that holds decrupted key data
func NewDecrypto(opts *crypto.Opts) (d *DeCrypto, err error) {
	d = &DeCrypto{
		Algos:  opts.EncType,
		DecKey: make([]byte, 32),
		SaltIter: SaltIter{
			Salt: make([]byte, 16),
			Iter: crypto.Pbkdf2Iter,
		},
	}

	if _, err = rand.Read(d.DecKey); err != nil {
		return
	}

	if _, err = rand.Read(d.Salt); err != nil {
		return
	}

	return
}

// EncryptKey encrypts a plaintext key with a passphrase and salt
func EncryptKey(d DeCrypto, opts *crypto.Opts) (e EnCrypto, err error) {
	if d.Algos != opts.EncType {
		err = utils.NewError("encryption type does not match decryption type", false)
		return
	}

	e.Algos = d.Algos
	e.Salt = d.Salt
	e.Iter = d.Iter

	passphrase, err := opts.GetPassphrase(crypto.StdinPassReader)
	if err != nil {
		return
	}

	ciphertextKey, err := crypto.Enckey(d.DecKey, e.Salt, e.Iter, passphrase)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	e.EncKey = base64.URLEncoding.EncodeToString(ciphertextKey)

	return
}
