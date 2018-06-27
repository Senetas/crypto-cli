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

package images

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"

	"github.com/Senetas/crypto-cli/utils"
)

// EncAlgo represents the collection of algorithms used for encryption and authentication
type EncAlgo string

const (
	// None represents an identity encryption function
	None EncAlgo = "NONE"
	// PassPBKDF2AESGCM represents encryption with AES-GCM with a key derived
	// from a passphrase using PBKDF2
	PassPBKDF2AESGCM EncAlgo = "PASS_PBKDF2_AES_GCM"
)

// ImageManifestJSON represents a docker image manifest schema v2.2
type ImageManifestJSON struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        *LayerJSON   `json:"config"`
	Layers        []*LayerJSON `json:"layers"`
}

// LayerJSON is the go type for an element in the layer array
type LayerJSON struct {
	Crypto      *CryptoJSON `json:"crypto,omitempty"`
	ContentType string      `json:"mediaType"`
	Size        int64       `json:"size"`
	Digest      string      `json:"digest"`
	filename    string
}

// CryptoJSON is the go type backing a crypto object in a manifest
type CryptoJSON struct {
	CryptoType EncAlgo `json:"cryptoType"`
	Key        string  `json:"key"`
}

func deckey(ciphertext []byte, pass, salt string) ([]byte, error) {
	nonce := ciphertext[:12]
	ckey := ciphertext[13:]

	bsalt := []byte(salt)

	key := utils.PassSalt2Key(pass, bsalt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ckey, bsalt)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func enckey(plaintext []byte, pass, salt string) ([]byte, error) {
	bsalt := []byte(salt)

	key := utils.PassSalt2Key(pass, bsalt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, bsalt)

	return concat([][]byte{nonce, ciphertext}), nil
}

func concat(slices [][]byte) []byte {
	var l int
	for _, s := range slices {
		l += len(s)
	}

	out := make([]byte, l)
	var i int
	for _, s := range slices {
		i += copy(out[i:], s)
	}
	return out
}

// NewCryptoJSON creates a new CryptoJSON struct by encrypting a plaintext key with a passphrase and salt
func newCryptoJSON(plaintextKey []byte, pass, salt string, cryptoType EncAlgo) (*CryptoJSON, error) {
	ciphertextKey, err := enckey(plaintextKey, pass, salt)
	if err != nil {
		return nil, err
	}
	crypto := &CryptoJSON{
		CryptoType: cryptoType,
		Key:        base64.URLEncoding.EncodeToString(ciphertextKey)}

	return crypto, nil
}

func newPlainLayerJSON(filename, digest string, size int64) (*LayerJSON, error) {
	layer := &LayerJSON{
		Size:     size,
		Digest:   digest,
		filename: filename}

	return layer, nil
}

func newLayerJSON(filename, digest string, size int64, plaintextKey []byte, pass, salt string) (*LayerJSON, error) {
	layer, err := newPlainLayerJSON(filename, digest, size)
	if err != nil {
		return nil, err
	}

	crypto, err := newCryptoJSON(plaintextKey, pass, salt, PassPBKDF2AESGCM)
	if err != nil {
		return nil, err
	}

	layer.Crypto = crypto

	return layer, nil
}

// NewConfigJSON creates a new LayerJSON for a config layer
func NewConfigJSON(filename, digest string, size int64, plaintextKey []byte, pass, salt string) (*LayerJSON, error) {
	layer, err := newLayerJSON(filename, digest, size, plaintextKey, pass, salt)
	if err != nil {
		return nil, err
	}

	layer.ContentType = "application/vnd.docker.container.image.v1+json"

	return layer, nil
}

// NewLayerJSON creates a new LayerJSON for a data layer
func NewLayerJSON(filename, digest string, size int64, plaintextKey []byte, pass, salt string) (*LayerJSON, error) {
	layer, err := newLayerJSON(filename, digest, size, plaintextKey, pass, salt)
	if err != nil {
		return nil, err
	}

	layer.ContentType = "application/vnd.docker.image.rootfs.diff.tar.gzip"

	return layer, nil
}

// NewPlainLayerJSON creates a new LayerJSON for an unencrypted data layer
func NewPlainLayerJSON(filename, digest string, size int64) (*LayerJSON, error) {
	layer, err := newPlainLayerJSON(filename, digest, size)
	if err != nil {
		return nil, err
	}

	layer.ContentType = "application/vnd.docker.image.rootfs.diff.tar.gzip"

	return layer, nil
}
