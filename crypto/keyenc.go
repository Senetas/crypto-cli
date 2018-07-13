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
	"crypto/rand"
	"crypto/sha256"

	"github.com/Senetas/crypto-cli/utils"
	"golang.org/x/crypto/pbkdf2"
)

// EncAlgo represents the collection of algorithms used for encryption and authentication
type EncAlgo string

const (
	// None represents an identity encryption function
	None EncAlgo = "NONE"
	// Pbkdf2Aes256Gcm represents aead with AES256-GCM with a key derived
	// from a passphrase using PBKDF2
	Pbkdf2Aes256Gcm EncAlgo = "PBKDF2-AES256-GCM"
)

// Deckey decrypts the ciphertext = key with the given passphrase and salt
func Deckey(ciphertext []byte, pass, salt string) ([]byte, error) {
	nonce := ciphertext[:12]
	ckey := ciphertext[12:]
	bsalt := []byte(salt)
	key := passSalt2Key(pass, bsalt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, utils.ErrDecrypt
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, utils.ErrDecrypt
	}

	plaintext, err := aesgcm.Open(nil, nonce, ckey, bsalt)
	if err != nil {
		return nil, utils.ErrDecrypt
	}

	return plaintext, nil
}

// Enckey encrypts the ciphertext = key with the given passphrase and salt
func Enckey(plaintext []byte, pass, salt string) ([]byte, error) {
	bsalt := []byte(salt)
	key := passSalt2Key(pass, bsalt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, utils.ErrEncrypt
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, utils.ErrEncrypt
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, utils.ErrEncrypt
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, bsalt)

	return utils.Concat([][]byte{nonce, ciphertext}), nil
}

// passSalt2Key deterministically returns a 32 byte encryption key given a passphrase and a salt
func passSalt2Key(pass string, salt []byte) []byte {
	return pbkdf2.Key([]byte(pass), salt, 8192, 32, sha256.New)
}
