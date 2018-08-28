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

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"

	"github.com/Senetas/crypto-cli/crypto"
)

func TestValidateAlgos(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		input string
		algo  crypto.Algos
		err   error
	}{
		{"NONE", crypto.None, nil},
		{"PBKDF2-AES256-GCM", crypto.Pbkdf2Aes256Gcm, nil},
		{"", crypto.Algos(""), errors.New("invalid encryption type")},
	}

	for _, test := range tests {
		algo, err := crypto.ValidateAlgos(test.input)
		if err != nil {
			assert.EqualError(err, test.err.Error())
		}
		assert.Equal(test.algo, algo)
	}
}
