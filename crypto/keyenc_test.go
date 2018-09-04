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
	"testing"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/stretchr/testify/require"
)

func TestKey(t *testing.T) {
	require := require.New(t)

	plaintext := []byte("Hello")
	salt := []byte("0123456789012345")

	ciphertext, err := crypto.Enckey([]byte(plaintext), salt, "hunter2")
	require.NoError(err)

	require.Equal(salt, ciphertext[:16])

	plaintext1, salt1, err := crypto.Deckey(ciphertext, "hunter2")
	require.NoError(err)

	require.Equal(salt, salt1)
	require.Equal(plaintext, plaintext1)
}
