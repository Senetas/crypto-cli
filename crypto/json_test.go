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

	"github.com/stretchr/testify/require"

	"github.com/Senetas/crypto-cli/crypto"
)

type test struct {
	A1, A2 string
	T1     test2
	C1     []int
}

type test2 struct {
	B1, B2 int
}

func TestJSONEncDec(t *testing.T) {
	require := require.New(t)

	o := test{
		A1: "hello",
		C1: []int{1, 2, 3},
	}

	key := make([]byte, 32)
	n, err := rand.Read(key)
	require.NoError(err)
	require.Equal(32, n)

	salt := make([]byte, 16)
	m, err := rand.Read(salt)
	require.NoError(err)
	require.Equal(16, m)

	str, err := crypto.EncryptJSON(o, key, salt)
	require.NoError(err)

	t.Log(str)
	o1 := test{}

	require.NoError(crypto.DecryptJSON(str, key, &o1))
	require.Equal(o, o1)
}
