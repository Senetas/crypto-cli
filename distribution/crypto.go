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
}

// DeCrypto is a decrypted key with the algotithms used to encrypt it and the data
type DeCrypto struct {
	Algos  crypto.Algos `json:"cryptoType"`
	DecKey []byte       `json:"-"`
}

// NewDecrypto create a new DeCrypto struct that holds decrupted key data
func NewDecrypto(opts *crypto.Opts) (*DeCrypto, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &DeCrypto{
		Algos:  opts.EncType,
		DecKey: key,
	}, nil
}

// EncryptKey encrypts a plaintext key with a passphrase and salt
func EncryptKey(d DeCrypto, opts *crypto.Opts) (EnCrypto, error) {
	e := EnCrypto{Algos: d.Algos}

	passphrase, err := opts.GetPassphrase()
	if err != nil {
		return EnCrypto{}, err
	}

	ciphertextKey, err := crypto.Enckey(d.DecKey, passphrase, opts.Salt)
	if err != nil {
		return EnCrypto{}, errors.WithStack(utils.ErrEncrypt)
	}

	e.EncKey = base64.URLEncoding.EncodeToString(ciphertextKey)

	return e, nil
}

// DecryptKey is the inverse function of EncryptKey (up to error)
func DecryptKey(e EnCrypto, opts *crypto.Opts) (DeCrypto, error) {
	if e.Algos != opts.EncType {
		return DeCrypto{}, utils.NewError("encryption type does not match decryption type", false)
	}

	d := DeCrypto{Algos: e.Algos}

	decoded, err := base64.URLEncoding.DecodeString(e.EncKey)
	if err != nil {
		return DeCrypto{}, errors.WithStack(utils.ErrDecrypt)
	}

	passphrase, err := opts.GetPassphrase()
	if err != nil {
		return DeCrypto{}, err
	}

	d.DecKey, err = crypto.Deckey(decoded, passphrase, opts.Salt)
	if err != nil {
		return DeCrypto{}, errors.WithStack(utils.ErrDecrypt)
	}

	return d, nil
}
