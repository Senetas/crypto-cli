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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strconv"

	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/pbkdf2"

	"github.com/Senetas/crypto-cli/utils"
)

const (
	// BaseCryptoURL is the base url to append query params to in compat mode
	BaseCryptoURL = "https://crypto.senetas.com/"

	// AlgosKey is the key used for the algos field in the url encoding of the crypto object
	AlgosKey = "algos"

	// VersionKey is the key used for the version field in the url encoding of the crypto object
	VersionKey = "version"

	// KeyKey is the key used for the (encrypted) data key in the url encoding of the crypto object
	KeyKey = "key"

	// NonceKey is the key used for the version field in the url encoding of the crypto object
	NonceKey = "nonce"

	// SaltKey is the key used for the version field in the url encoding of the crypto object
	SaltKey = "salt"

	// ItersKey is the key used for the version field in the url encoding of the crypto object
	ItersKey = "iters"
)

// Crypto contains the common parts of EnCrypto and DeCrypto
type Crypto struct {
	Algos   Algos  `json:"algos"`
	Nonce   []byte `json:"nonce"`
	Salt    []byte `json:"salt"`
	Iters   int    `json:"iters"`
	Version int    `json:"version"`
}

// EnCrypto is a encrypted key with the algotithms used to encrypt it and the data
type EnCrypto struct {
	Crypto
	EncKey []byte `json:"key"`
}

// NewEncryptoCompat create a new Encrypto struct from some URLs
func NewEncryptoCompat(urls []string, opts *Opts) (e EnCrypto, err error) {
	if len(urls) == 0 {
		err = errors.New("missing encryption key")
		return
	}

	u, err := url.Parse(urls[0])
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	e.Algos, err = ValidateAlgos(u.Query().Get(AlgosKey))
	if err != nil {
		return
	}

	if e.Algos != opts.Algos {
		err = utils.NewError("encryption type does not match decryption type", false)
		return
	}

	e.EncKey, err = base64.URLEncoding.DecodeString(u.Query().Get(KeyKey))
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	e.Nonce, err = base64.URLEncoding.DecodeString(u.Query().Get(NonceKey))
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	e.Salt, err = base64.URLEncoding.DecodeString(u.Query().Get(SaltKey))
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	e.Iters, err = strconv.Atoi(u.Query().Get(ItersKey))
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	e.Version, err = strconv.Atoi(u.Query().Get(VersionKey))
	if err != nil {
		err = errors.WithStack(err)
	}

	return
}

// NewURLCompat creates a url from an EnCrypto struct
func NewURLCompat(e *EnCrypto, opts *Opts) (u *url.URL, err error) {
	u, err = url.Parse(BaseCryptoURL)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	v := url.Values{}
	v.Set(AlgosKey, string(e.Algos))
	v.Set(KeyKey, base64.URLEncoding.EncodeToString(e.EncKey))
	v.Set(NonceKey, base64.URLEncoding.EncodeToString(e.Nonce))
	v.Set(SaltKey, base64.URLEncoding.EncodeToString(e.Salt))
	v.Set(ItersKey, strconv.Itoa(e.Iters))
	v.Set(VersionKey, strconv.Itoa(e.Version))
	u.RawQuery = v.Encode()
	return
}

// DecryptKey is the inverse function of EncryptKey (up to error)
func DecryptKey(e EnCrypto, opts *Opts) (d DeCrypto, err error) {
	if e.Algos != opts.Algos {
		err = utils.NewError("encryption type does not match decryption type", false)
		return
	}

	passphrase, err := opts.GetPassphrase(StdinPassReader)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	d.Crypto = e.Crypto

	log.Debug().Msgf("%s", spew.Sdump(e))
	log.Debug().Msgf("%s", spew.Sdump(d))

	if vD, ok := versionDataStore[d.Version]; !ok {
		err = errors.New("unknown version")
	} else {
		if vD.saltLength != len(d.Salt) {
			err = errors.New("salt is wrong length")
			return
		}

		if vD.nonceLength != len(d.Nonce) {
			err = errors.New("nonce is wrong length")
			return
		}

		d.DecKey, err = deckey(e.EncKey, e.Nonce, e.Salt, e.Iters, passphrase)
		if err != nil {
			err = errors.WithStack(err)
		}
	}

	return
}

// deckey decrypts the ciphertext (=encrpted data key) with the given passphrase and salt
func deckey(
	ciphertext, nonce, salt []byte,
	iter int,
	pass string,
) (
	plaintext []byte,
	err error,
) {
	kek := passSalt2Key(pass, salt, iter)

	block, err := aes.NewCipher(kek)
	if err != nil {
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	return aesgcm.Open(nil, nonce, ciphertext, salt)
}

// DeCrypto is a decrypted key with the algotithms used to encrypt it and the data
type DeCrypto struct {
	Crypto
	DecKey []byte `json:"-"`
}

// NewDecrypto create a new DeCrypto struct that holds decrupted key data
func NewDecrypto(opts *Opts) (d *DeCrypto, err error) {
	d = &DeCrypto{
		Crypto: Crypto{
			Algos:   opts.Algos,
			Version: opts.Version,
			Nonce:   make([]byte, 12),
			Salt:    make([]byte, 16),
			Iters:   Pbkdf2Iter,
		},
		DecKey: make([]byte, 32),
	}

	if _, err = rand.Read(d.DecKey); err != nil {
		err = errors.WithStack(err)
		return
	}

	if _, err = rand.Read(d.Nonce); err != nil {
		err = errors.WithStack(err)
		return
	}

	if _, err = rand.Read(d.Salt); err != nil {
		err = errors.WithStack(err)
	}

	return
}

// EncryptKey encrypts a plaintext key with a passphrase and salt
func EncryptKey(d DeCrypto, opts *Opts) (e EnCrypto, err error) {
	if d.Algos != opts.Algos {
		err = utils.NewError("encryption type does not match decryption type", false)
		return
	}

	passphrase, err := opts.GetPassphrase(StdinPassReader)
	if err != nil {
		return
	}

	e.Crypto = d.Crypto
	e.EncKey, err = enckey(d.DecKey, e.Nonce, e.Salt, e.Iters, passphrase)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	return
}

// enckey encrypts the plaintext (= data key) with the given passphrase and salt
func enckey(
	plaintext, nonce, salt []byte,
	iters int,
	pass string,
) (
	ciphertext []byte,
	err error,
) {
	kek := passSalt2Key(pass, salt, iters)

	block, err := aes.NewCipher(kek)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		err = errors.WithStack(err)
		return
	}

	return aesgcm.Seal(nil, nonce, plaintext, salt), nil
}

// passSalt2Key deterministically returns a 32 byte encryption key given a passphrase and a salt
func passSalt2Key(pass string, salt []byte, iter int) []byte {
	return pbkdf2.Key([]byte(pass), salt, iter, 32, sha256.New)
}
