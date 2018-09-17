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
	"encoding/base64"
	"encoding/json"

	"github.com/pkg/errors"
)

// EncryptJSON encrypts a JSON object and base64 (URL) encodes the ciphertext
func EncryptJSON(val interface{}, key, nonce, salt []byte) (ciphertext string, err error) {
	plaintext, err := json.Marshal(val)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	ciphertext = base64.URLEncoding.EncodeToString(aesgcm.Seal(nil, nonce, plaintext, salt))

	return
}

// DecryptJSON decrypts a string that is the base64 (URL) encoded ciphertext of
// a json object and assigns that object to val
func DecryptJSON(ciphertext string, key, nonce, salt []byte, val interface{}) (err error) {
	decoded, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	plaintext, err := aesgcm.Open(nil, nonce, decoded, salt)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	if err = json.Unmarshal(plaintext, val); err != nil {
		err = errors.WithStack(err)
		return
	}

	return
}
