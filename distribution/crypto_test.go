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

package distribution_test

import (
	"reflect"
	"testing"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/distribution"
)

func TestCrypto(t *testing.T) {
	plaintext := []byte("196884 = 196883 + 1")
	c := &distribution.Crypto{
		Algos:  crypto.Pbkdf2Aes256Gcm,
		DecKey: plaintext,
	}

	if err := c.Encrypt("hunter2", "saltysaltysaltysalty", crypto.Pbkdf2Aes256Gcm); err != nil {
		t.Error(err)
	}

	d := c // make a copy

	if err := d.Decrypt("hunter2", "saltysaltysaltysalty", crypto.Pbkdf2Aes256Gcm); err != nil {
		t.Error(err)
	}

	if !reflect.DeepEqual(c, d) {
		t.Errorf("inversion failed, c = %s, d = %s", c, d)
	}
}
