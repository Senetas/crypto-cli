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

package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"

	"github.com/minio/sio"
)

// Sha256sum calculates the sha256 incrementally, returns a string
func Sha256sum(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// Pass2KeySalt creates a byte sequence suitible for use as a key from a passphrase
// also returns the salt
func Pass2KeySalt(pass string) ([]byte, []byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	return PassSalt2Key(pass, salt), salt, nil
}

// PassSalt2Key deterministically returns a 32 byte encryption key given a passphrase and a salt
func PassSalt2Key(pass string, salt []byte) []byte {
	return pbkdf2.Key([]byte(pass), salt, 8192, 32, sha256.New)
}

// EncFile encrypts the file inName to outName with a random 32 byte key. returns the key
func EncFile(inName, outName string) ([]byte, int64, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, 0, err
	}

	infile, err := os.Open(inName)
	if err != nil {
		return nil, 0, err
	}
	defer infile.Close()

	outfile, err := os.Create(outName)
	if err != nil {
		return nil, 0, err
	}
	defer outfile.Close()

	cfg := sio.Config{
		MinVersion:   sio.Version20,
		MaxVersion:   sio.Version20,
		CipherSuites: []byte{sio.AES_256_GCM},
		Key:          key}

	outenc, err := sio.EncryptWriter(outfile, cfg)
	if err != nil {
		return nil, 0, err
	}

	size, err := io.Copy(outenc, infile)
	if err != nil {
		return nil, 0, err
	}

	if err = outenc.Close(); err != nil {
		infile.Close()
		outfile.Close()
		os.Remove(outName)
		return nil, 0, err
	}

	return key, size, nil
}

// DecFile decrypts (and authenticates) infile and writes it to outfile
// only persists if the decrypttion and authentication suceedes
func DecFile(inName, outName string, datakey []byte) error {
	infile, err := os.Open(inName)
	if err != nil {
		return err
	}
	defer infile.Close()

	outfile, err := os.Create(outName)
	if err != nil {
		return err
	}
	defer outfile.Close()

	cfg := sio.Config{
		MinVersion:   sio.Version20,
		MaxVersion:   sio.Version20,
		CipherSuites: []byte{sio.AES_256_GCM},
		Key:          datakey}

	outdec, err := sio.DecryptWriter(infile, cfg)
	if err != nil {
		return err
	}

	if _, err = io.Copy(outdec, outfile); err != nil {
		return err
	}

	if err = outdec.Close(); err != nil {
		infile.Close()
		outfile.Close()
		os.Remove(outName)
		return err
	}

	return nil
}
