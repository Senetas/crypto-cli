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

	"github.com/Senetas/crypto-cli/utils"
)

// EncAlgo represents the collection of algorithms used for encryption and authentication
type EncAlgo string

const (
	// None represents an identity encryption function
	None EncAlgo = "NONE"
	// PassPBKDF2AESGCM represents encryption with AES-GCM with a key derived
	// from a passphrase using PBKDF2
	PassPBKDF2AESGCM EncAlgo = "PASS_PBKDF2_AES_GCM"
)

func Deckey(ciphertext []byte, pass, salt string) ([]byte, error) {
	nonce := ciphertext[:12]
	ckey := ciphertext[12:]

	bsalt := []byte(salt)

	key := PassSalt2Key(pass, bsalt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ckey, bsalt)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func Enckey(plaintext []byte, pass, salt string) ([]byte, error) {
	bsalt := []byte(salt)

	key := PassSalt2Key(pass, bsalt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, bsalt)

	return utils.Concat([][]byte{nonce, ciphertext}), nil
}
