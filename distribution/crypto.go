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

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/utils"
	"github.com/pkg/errors"
)

// EnCrypto is a encrypted key with the algotithms used to encrypt it and the data
type EnCrypto struct {
	Algos  crypto.Algos `json:"cryptoType"`
	EncKey string       `json:"key"`
	Salt   []byte       `json:"-"`
}

// DecryptKey is the inverse function of EncryptKey (up to error)
func DecryptKey(e EnCrypto, opts *crypto.Opts) (d DeCrypto, err error) {
	if e.Algos != opts.EncType {
		return DeCrypto{}, utils.NewError("encryption type does not match decryption type", false)
	}

	decoded, err := base64.URLEncoding.DecodeString(e.EncKey)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	passphrase, err := opts.GetPassphrase(crypto.StdinPassReader)
	if err != nil {
		return
	}

	d = DeCrypto{Algos: e.Algos}
	d.DecKey, d.Salt, err = crypto.Deckey(decoded, passphrase)
	if err != nil {
		return
	}

	return
}

// DeCrypto is a decrypted key with the algotithms used to encrypt it and the data
type DeCrypto struct {
	Algos  crypto.Algos `json:"cryptoType"`
	DecKey []byte       `json:"-"`
	Salt   []byte       `json:"-"`
}

// NewDecrypto create a new DeCrypto struct that holds decrupted key data
func NewDecrypto(opts *crypto.Opts) (d *DeCrypto, err error) {
	d = &DeCrypto{
		Algos:  opts.EncType,
		DecKey: make([]byte, 32),
		Salt:   make([]byte, 16),
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
	e.Algos = d.Algos
	e.Salt = d.Salt

	passphrase, err := opts.GetPassphrase(crypto.StdinPassReader)
	if err != nil {
		return
	}

	ciphertextKey, err := crypto.Enckey(d.DecKey, e.Salt, passphrase)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	e.EncKey = base64.URLEncoding.EncodeToString(ciphertextKey)

	return
}
