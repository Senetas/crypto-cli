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
	"encoding/base64"
	"encoding/json"

	"github.com/Senetas/crypto-cli/utils"
)

// EncryptJSON encrypts a JSON object and base64 (URL) encodes the ciphertext
func EncryptJSON(val interface{}, key, ad []byte) (string, error) {
	plaintext, err := json.Marshal(val)
	if err != nil {
		return "", utils.ErrEncrypt
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", utils.ErrEncrypt
	}

	// create random nonce
	nonce := make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return "", utils.ErrEncrypt
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", utils.ErrEncrypt
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, ad)
	noncecipher := utils.Concat([][]byte{nonce, ciphertext})
	return base64.URLEncoding.EncodeToString(noncecipher), nil
}

// DecryptJSON decrypts a string that is the base64 (URL) encoded ciphertext of a json object
func DecryptJSON(ciphertext string, key, ad []byte, val interface{}) error {
	decoded, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return utils.ErrDecrypt
	}

	nonce := decoded[:12]
	cjstr := decoded[12:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return utils.ErrDecrypt
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return utils.ErrDecrypt
	}

	plaintext, err := aesgcm.Open(nil, nonce, cjstr, ad)
	if err != nil {
		return utils.ErrDecrypt
	}

	if err = json.Unmarshal(plaintext, val); err != nil {
		return utils.ErrDecrypt
	}

	return nil
}
