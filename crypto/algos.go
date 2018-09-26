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
	"github.com/pkg/errors"
)

// Algos represents the collection of algorithms used for encryption and authentication
type Algos string

const (
	// None represents an identity encryption function
	None Algos = "NONE"

	// Pbkdf2Aes256Gcm represents aead with AES256-GCM with a key derived
	// from a passphrase using PBKDF2
	Pbkdf2Aes256Gcm Algos = "PBKDF2-AES256-GCM"

	// Pbkdf2Iter is the number of iterations of PBKDF2 to run
	Pbkdf2Iter = 4e4
)

type versionData struct {
	saltLength  int
	nonceLength int
}

var versionDataStore = map[int]versionData{0: {saltLength: 16, nonceLength: 12}}

// ValidateAlgos converts a string to valid Algos if possible
func ValidateAlgos(ctstr string) (Algos, error) {
	if ctstr == string(None) {
		return None, nil
	} else if ctstr == string(Pbkdf2Aes256Gcm) {
		return Pbkdf2Aes256Gcm, nil
	}
	return Algos(""), errors.New("invalid encryption type")
}
