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
	"fmt"
	"syscall"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh/terminal"
)

// Algos represents the collection of algorithms used for encryption and authentication
type Algos string

const (
	// None represents an identity encryption function
	None Algos = "NONE"
	// Pbkdf2Aes256Gcm represents aead with AES256-GCM with a key derived
	// from a passphrase using PBKDF2
	Pbkdf2Aes256Gcm Algos = "PBKDF2-AES256-GCM"
)

// ValidateAlgos converts a string to valid Algos if possible
func ValidateAlgos(ctstr string) (Algos, error) {
	if ctstr == string(None) {
		return None, nil
	} else if ctstr == string(Pbkdf2Aes256Gcm) {
		return Pbkdf2Aes256Gcm, nil
	}
	return Algos(""), errors.New("invalid encryption type")
}

// Opts stores data necessary for encryption
type Opts struct {
	// whether the encryption data should be stored in a v2.2 compatible manifest or not
	Compat        bool
	passphraseSet bool
	passphrase    string
	Salt          string
	EncType       Algos
}

// SetPassphrase sets the passphrase
func (o *Opts) SetPassphrase(passphrase string) {
	o.passphrase = passphrase
	o.passphraseSet = true
}

// GetPassphrase prompt the user to enter a passphrase to decrypt
func (o *Opts) GetPassphrase() (_ string, err error) {
	log.Debug().Msgf("%#v", o)
	if !o.passphraseSet {
		o.passphrase, err = GetPassSTDIN("Enter passphrase: ")
		if err != nil {
			return "", err
		}
		o.passphraseSet = true
	}
	return o.passphrase, nil
}

// GetPassSTDIN prompte the user for a passphrase
func GetPassSTDIN(prompt string) (_ string, err error) {
	fmt.Print(prompt)
	passphrase := []byte{}
	for len(passphrase) == 0 {
		passphrase, err = terminal.ReadPassword(syscall.Stdin)
		if err != nil {
			return "", errors.WithStack(err)
		}
		fmt.Println()
	}
	return string(passphrase), err
}
