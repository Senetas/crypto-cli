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
	"encoding/base64"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/utils"
	"github.com/pkg/errors"
)

// Crypto is the go type backing a crypto object in a manifest
type Crypto struct {
	Algos  crypto.Algos `json:"cryptoType"`
	EncKey string       `json:"key"`
	DecKey []byte       `json:"-"`
}

// Encrypt creates a new CryptoJSON struct by encrypting a plaintext key with a passphrase and salt
func (c *Crypto) Encrypt(pass, salt string, algos crypto.Algos) error {
	ciphertextKey, err := crypto.Enckey(c.DecKey, pass, salt)
	if err != nil {
		return errors.WithStack(utils.ErrEncrypt)
	}

	c.EncKey = base64.URLEncoding.EncodeToString(ciphertextKey)
	c.Algos = algos

	return nil
}

// Decrypt is the inverse function of Encrypt (up to error, types etc)
func (c *Crypto) Decrypt(pass, salt string, algos crypto.Algos) error {
	if c.Algos != algos {
		return utils.NewError("encryption type does not match decryption type", false)
	}

	decoded, err := base64.URLEncoding.DecodeString(c.EncKey)
	if err != nil {
		return errors.WithStack(utils.ErrDecrypt)
	}

	c.DecKey, err = crypto.Deckey(decoded, pass, salt)
	if err != nil {
		return errors.WithStack(utils.ErrDecrypt)
	}

	return nil
}
