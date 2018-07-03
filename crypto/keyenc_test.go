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

package crypto_test

import (
	"bytes"
	"testing"

	"github.com/Senetas/crypto-cli/crypto"
)

func TestKey(t *testing.T) {
	plaintext := []byte("Hello")
	salt := "com.senetas.crypto/narthanaepa1/my-alpine/test/config"
	ciphertext, err := crypto.Enckey([]byte(plaintext), "hunter2", salt)
	if err != nil {
		panic(err)
	}

	plaintext1, err := crypto.Deckey(ciphertext, "hunter2", salt)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(plaintext, plaintext1) {
		t.Errorf("plaintext %s was encrypted to %v which decrypted to %s", plaintext, ciphertext, plaintext1)
	}
}
