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
	"golang.org/x/crypto/ssh/terminal"
)

// StdinPassReader reads a password from stdin
var StdinPassReader = func() ([]byte, error) { return terminal.ReadPassword(syscall.Stdin) }

// Opts stores data necessary for encryption
type Opts struct {
	// whether the encryption data should be stored in a v2.2 compatible manifest or not
	Compat        bool
	passphraseSet bool
	passphrase    string
	Version       int
	Algos         Algos
	Iter          int
}

// SetPassphrase sets the passphrase
func (o *Opts) SetPassphrase(passphrase string) {
	o.passphrase = passphrase
	o.passphraseSet = true
}

// GetPassphrase prompt the user to enter a passphrase to decrypt
func (o *Opts) GetPassphrase(passReader func() ([]byte, error)) (_ string, err error) {
	if !o.passphraseSet {
		o.passphrase, err = GetPassSTDIN("Enter passphrase: ", passReader)
		if err != nil {
			return
		}
		o.passphraseSet = true
	}
	return o.passphrase, nil
}

// GetPassSTDIN prompte the user for a passphrase
func GetPassSTDIN(prompt string, passReader func() ([]byte, error)) (_ string, err error) {
	fmt.Print(prompt)
	passphrase := []byte{}
	for len(passphrase) == 0 {
		passphrase, err = passReader()
		if err != nil {
			return "", errors.WithStack(err)
		}
		fmt.Println()
	}
	return string(passphrase), err
}
