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
	digest "github.com/opencontainers/go-digest"

	"github.com/Senetas/crypto-cli/crypto"
)

// Layer is the go type for an element in the layer array
type Layer struct {
	Crypto      *Crypto        `json:"crypto,omitempty"`
	ContentType string         `json:"mediaType"`
	Size        int64          `json:"size"`
	Digest      *digest.Digest `json:"digest"`
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
		CryptoType: crypto.Pbkdf2Aes256Gcm,
		DecKey:     plaintextKey,
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
