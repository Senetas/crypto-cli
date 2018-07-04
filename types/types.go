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

package types

import (
	"encoding/base64"

	digest "github.com/opencontainers/go-digest"

	"github.com/Senetas/crypto-cli/crypto"
)

// ArchiveManifest represents the json manifest in an image archive
// such as that produced by docker save
type ArchiveManifest struct {
	Config   string
	RepoTags []string
	Layers   []string
}

// ImageManifestJSON represents a docker image manifest schema v2.2
type ImageManifestJSON struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        *LayerJSON   `json:"config"`
	Layers        []*LayerJSON `json:"layers"`
	DirName       string       `json:"-"`
}

// LayerJSON is the go type for an element in the layer array
type LayerJSON struct {
	Crypto      *CryptoJSON    `json:"crypto,omitempty"`
	ContentType string         `json:"mediaType"`
	Size        int64          `json:"size"`
	Digest      *digest.Digest `json:"digest"`
	Filename    string         `json:"-"`
}

// CryptoJSON is the go type backing a crypto object in a manifest
type CryptoJSON struct {
	CryptoType crypto.EncAlgo `json:"cryptoType"`
	EncKey     string         `json:"key"`
	DecKey     []byte         `json:"-"`
}

// DeCryptoData stores the decrypted data keys after decrypting a crypto object
type DeCryptoData struct {
	CryptoType crypto.EncAlgo
	Key        []byte
}

// Encrypt creates a new CryptoJSON struct by encrypting a plaintext key with a passphrase and salt
func (c *CryptoJSON) Encrypt(pass, salt string) error {
	ciphertextKey, err := crypto.Enckey(c.DecKey, pass, salt)
	if err != nil {
		return err
	}

	c.EncKey = base64.URLEncoding.EncodeToString(ciphertextKey)

	return nil
}

// Decrypt is the inverse function of Encrypt (up to error, types etc)
func (c *CryptoJSON) Decrypt(pass, salt string) error {
	decoded, err := base64.URLEncoding.DecodeString(c.EncKey)
	if err != nil {
		return err
	}

	c.DecKey, err = crypto.Deckey(decoded, pass, salt)
	if err != nil {
		return err
	}

	return nil
}

func newPlainLayerJSON(filename string, d *digest.Digest, size int64) *LayerJSON {
	layer := &LayerJSON{
		Size:     size,
		Digest:   d,
		Filename: filename}
	return layer
}

func newLayerJSON(filename string, d *digest.Digest, size int64, plaintextKey []byte) *LayerJSON {
	layer := newPlainLayerJSON(filename, d, size)
	layer.Crypto = &CryptoJSON{
		CryptoType: crypto.Pbkdf2Aes256Gcm,
		DecKey:     plaintextKey,
	}
	return layer
}

// NewConfigJSON creates a new LayerJSON for a config layer
func NewConfigJSON(filename string, d *digest.Digest, size int64, plaintextKey []byte) *LayerJSON {
	layer := newLayerJSON(filename, d, size, plaintextKey)
	layer.ContentType = "application/vnd.docker.container.image.v1+json"
	return layer
}

// NewLayerJSON creates a new LayerJSON for a data layer
func NewLayerJSON(filename string, d *digest.Digest, size int64, plaintextKey []byte) *LayerJSON {
	layer := newLayerJSON(filename, d, size, plaintextKey)
	layer.ContentType = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	return layer
}

// NewPlainLayerJSON creates a new LayerJSON for an unencrypted data layer
func NewPlainLayerJSON(filename string, d *digest.Digest, size int64) *LayerJSON {
	layer := newPlainLayerJSON(filename, d, size)
	layer.ContentType = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	return layer
}
