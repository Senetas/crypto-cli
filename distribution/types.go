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
	"encoding/base64"

	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/utils"
)

// ArchiveManifest represents the json manifest in an image archive
// such as that produced by docker save
type ArchiveManifest struct {
	Config   string
	RepoTags []string
	Layers   []string
}

// ImageManifest represents a docker image manifest schema v2.2
type ImageManifest struct {
	SchemaVersion int      `json:"schemaVersion"`
	MediaType     string   `json:"mediaType"`
	Config        *Layer   `json:"config"`
	Layers        []*Layer `json:"layers"`
	DirName       string   `json:"-"`
}

// Layer is the go type for an element in the layer array
type Layer struct {
	Crypto      *Crypto        `json:"crypto,omitempty"`
	ContentType string         `json:"mediaType"`
	Size        int64          `json:"size"`
	Digest      *digest.Digest `json:"digest"`
	Filename    string         `json:"-"`
}

// Crypto is the go type backing a crypto object in a manifest
type Crypto struct {
	CryptoType crypto.EncAlgo `json:"cryptoType"`
	EncKey     string         `json:"key"`
	DecKey     []byte         `json:"-"`
}

// DeCrypto stores the decrypted data keys after decrypting a crypto object
type DeCrypto struct {
	CryptoType crypto.EncAlgo
	Key        []byte
}

// Encrypt creates a new CryptoJSON struct by encrypting a plaintext key with a passphrase and salt
func (c *Crypto) Encrypt(pass, salt string, cryptotype crypto.EncAlgo) error {
	ciphertextKey, err := crypto.Enckey(c.DecKey, pass, salt)
	if err != nil {
		return errors.WithStack(utils.ErrEncrypt)
	}

	c.EncKey = base64.URLEncoding.EncodeToString(ciphertextKey)
	c.CryptoType = cryptotype

	return nil
}

// Decrypt is the inverse function of Encrypt (up to error, types etc)
func (c *Crypto) Decrypt(pass, salt string, cryptotype crypto.EncAlgo) error {
	if c.CryptoType != cryptotype {
		return utils.NewError("encryption type does not match decryption type", false)
	}

	decoded, err := base64.URLEncoding.DecodeString(c.EncKey)
	if err != nil {
		return errors.WithStack(utils.ErrDecrypt)
	}

	c.DecKey, err = crypto.Deckey(decoded, pass, salt)
	if err != nil {
		return errors.WithStack(utils.ErrDecrypt)
	}

	return nil
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
	layer.ContentType = "application/vnd.docker.container.image.v1+json"
	return layer
}

// NewLayer creates a new LayerJSON for a data layer
func NewLayer(filename string, d *digest.Digest, size int64, plaintextKey []byte) *Layer {
	layer := newLayer(filename, d, size, plaintextKey)
	layer.ContentType = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	return layer
}

// NewPlainLayer creates a new LayerJSON for an unencrypted data layer
func NewPlainLayer(filename string, d *digest.Digest, size int64) *Layer {
	layer := newPlainLayer(filename, d, size)
	layer.ContentType = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	return layer
}
