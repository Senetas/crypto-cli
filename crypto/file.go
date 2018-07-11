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
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"github.com/minio/sio"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"

	"github.com/Senetas/crypto-cli/utils"
)

// Sha256sum calculates the sha256 incrementally, returns a string
func Sha256sum(file string) (s string, err error) {
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer func() {
		err = utils.CheckedClose(f, err)
	}()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// PassSalt2Key deterministically returns a 32 byte encryption key given a passphrase and a salt
func PassSalt2Key(pass string, salt []byte) []byte {
	return pbkdf2.Key([]byte(pass), salt, 8192, 32, sha256.New)
}

//GenDataKey generates a random key for data encryption
func GenDataKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncFile encrypts the file inName to outName with a random 32 byte key. returns the key
// assumes infile and outfile use they system seperator
func EncFile(infile, outfile string, key []byte) (d *digest.Digest, size int64, err error) {
	inFH, err := os.Open(infile)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		err = utils.CheckedClose(inFH, err)
	}()

	outFH, err := os.Create(outfile)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		err = utils.CheckedClose(outFH, err)
	}()

	cfg := sio.Config{
		MinVersion:   sio.Version20,
		MaxVersion:   sio.Version20,
		CipherSuites: []byte{sio.AES_256_GCM},
		Key:          key,
	}

	digester := digest.Canonical.Digester()
	mw := io.MultiWriter(digester.Hash(), outFH)
	size, err = sio.Encrypt(mw, inFH, cfg)

	ds := digester.Digest()
	return &ds, size, nil
}

// DecFile decrypts (and authenticates) infile and writes it to outfile
// only persists if the decrypttion and authentication suceedes
// assumes infile and outfile use they system seperator
func DecFile(infile, outfile string, datakey []byte) (err error) {
	inFH, err := os.Open(infile)
	if err != nil {
		return err
	}
	defer func() {
		err = utils.CheckedClose(inFH, err)
	}()

	outFH, err := os.Create(outfile)
	if err != nil {
		return err
	}
	defer func() {
		err = utils.CheckedClose(outFH, err)
	}()

	cfg := sio.Config{
		MinVersion:   sio.Version20,
		MaxVersion:   sio.Version20,
		CipherSuites: []byte{sio.AES_256_GCM},
		Key:          datakey}

	if _, err = sio.Decrypt(outFH, inFH, cfg); err != nil {
		if err2 := outFH.Close(); err2 != nil {
			err = utils.CombineErr([]error{err, err2})
		}
		if err2 := os.Remove(outfile); err2 != nil {
			err2 = errors.Wrapf(err2, "warning, unauthenticated file could not be removed: %s", outfile)
			err = utils.CombineErr([]error{err, err2})
		}
		return err
	}

	return nil
}
