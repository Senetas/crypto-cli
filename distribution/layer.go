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

package distribution

import (
	"net/url"

	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/crypto"
)

const (
	// AlgosKey is the key used for the algos field in the url encoding of the crypto object
	AlgosKey = "algos"
	// KeyKey is the key used for the (encrypted) data key in the url encoding of the crypto object
	KeyKey = "key"
)

// Layer is the go type for an element in the layer array
type Layer struct {
	Crypto      *Crypto        `json:"crypto,omitempty"`
	ContentType string         `json:"mediaType"`
	Size        int64          `json:"size"`
	Digest      *digest.Digest `json:"digest"`
	URLs        []string       `json:"urls,omitempty"`
	Filename    string         `json:"-"`
}

func newPlainLayer(filename string, d *digest.Digest, size int64) *Layer {
	layer := &Layer{
		Size:     size,
		Digest:   d,
		Filename: filename,
	}
	return layer
}

func newLayer(filename string, d *digest.Digest, size int64, plaintextKey []byte) *Layer {
	layer := newPlainLayer(filename, d, size)
	layer.Crypto = &Crypto{
		Algos:  crypto.Pbkdf2Aes256Gcm,
		DecKey: plaintextKey,
	}
	return layer
}

// NewConfig creates a new Layer for a config layer
func NewConfig(filename string, d *digest.Digest, size int64, plaintextKey []byte) *Layer {
	layer := newLayer(filename, d, size, plaintextKey)
	layer.ContentType = MediaTypeImageConfig
	return layer
}

// NewLayer creates a new LayerJSON for a data layer
func NewLayer(filename string, d *digest.Digest, size int64, plaintextKey []byte) *Layer {
	layer := newLayer(filename, d, size, plaintextKey)
	layer.ContentType = MediaTypeLayer
	return layer
}

// NewPlainLayer creates a new LayerJSON for an unencrypted data layer
func NewPlainLayer(filename string, d *digest.Digest, size int64) *Layer {
	layer := newPlainLayer(filename, d, size)
	layer.ContentType = MediaTypeLayer
	return layer
}

// Encrypt encrypts the key for the layer
func (l *Layer) Encrypt(opts crypto.Opts) error {
	if err := l.Crypto.Encrypt(opts.Passphrase, opts.Salt, opts.EncType); err != nil {
		return err
	}

	if opts.Compat {
		u, err := url.Parse(BaseCryptoURL)
		if err != nil {
			return errors.WithStack(err)
		}

		v := url.Values{}
		v.Set(AlgosKey, string(l.Crypto.Algos))
		v.Set(KeyKey, l.Crypto.EncKey)
		u.RawQuery = v.Encode()
		l.URLs = []string{u.String()}
		l.Crypto = nil
	}
	return nil
}

// Decrypt encrypts the key for the layer
func (l *Layer) Decrypt(opts crypto.Opts) error {
	if l.Crypto == nil {
		if len(l.URLs) == 0 {
			return errors.New("no crypto data found")
		}
		u, err := url.Parse(l.URLs[0])
		if err != nil {
			return errors.WithStack(err)
		}

		algos, err := crypto.ValidateAlgos(u.Query().Get(AlgosKey))
		if err != nil {
			return errors.WithStack(err)
		}

		l.Crypto = &Crypto{
			Algos:  algos,
			EncKey: u.Query().Get(KeyKey),
		}
		l.URLs = nil
	}

	if err := l.Crypto.Decrypt(opts.Passphrase, opts.Salt, opts.EncType); err != nil {
		return err
	}

	return nil
}
