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

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"

	"github.com/Senetas/crypto-cli/utils"
	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

// Enckey encrypts the ciphertext = key with the given passphrase and salt
func Enckey(plaintext, salt []byte, pass string) (ciphertext []byte, err error) {
	key := passSalt2Key(pass, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	nonce := make([]byte, 12)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	cipherkey := aesgcm.Seal(nil, nonce, plaintext, salt)

	return utils.Concat([][]byte{salt, nonce, cipherkey}), nil
}

// Deckey decrypts the ciphertext = key with the given passphrase and salt
func Deckey(ciphertext []byte, pass string) (plaintext, salt []byte, err error) {
	salt = ciphertext[:16]
	nonce := ciphertext[16:28]
	key := ciphertext[28:]

	kek := passSalt2Key(pass, salt)

	block, err := aes.NewCipher(kek)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	plaintext, err = aesgcm.Open(nil, nonce, key, salt)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	return
}

// passSalt2Key deterministically returns a 32 byte encryption key given a passphrase and a salt
func passSalt2Key(pass string, salt []byte) []byte {
	return pbkdf2.Key([]byte(pass), salt, 8192, 32, sha256.New)
}
