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
	"crypto/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/utils"
)

func TestJSONEncDec(t *testing.T) {
	assert := assert.New(t)

	type test2 struct {
		B1, B2 int
	}

	type test struct {
		A1, A2 string
		T1     test2
		C1     []int
	}

	o := test{
		A1: "hello",
		C1: []int{1, 2, 3},
	}

	var key [32]byte
	n, err := rand.Read(key[:])
	if err != nil {
		t.Fatalf("%+v", err)
	} else if n != 32 {
		t.Fatal("failed to read 32 random bytes")
	}

	str, err := crypto.EncryptJSON(o, key[:], []byte("hello"))
	if err != nil {
		assert.Equal(err, utils.ErrEncrypt)
		t.Fatalf("%+v", err)
	}

	t.Log(str)

	o1 := test{}

	if err = crypto.DecryptJSON(str, key[:], []byte("hello"), &o1); err != nil {
		assert.Equal(err, utils.ErrDecrypt)
		t.Fatalf("%+v", err)
	}

	if !cmp.Equal(o, o1) {
		t.Fatalf("Decryption did not invert Encryption\no = %#v, o1 = %#v", o, o1)
	}
}
