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
	"io"
	"os"

	digest "github.com/opencontainers/go-digest"

	"github.com/Senetas/crypto-cli/crypto"
)

// Blob represents an entry for a blob in the image manifest
type Blob interface {
	GetMediaType() string
	GetDigest() digest.Digest
	GetSize() int64
	GetFilename() string
	SetFilename(filename string)
	ReadCloser() (io.ReadCloser, error)
}

// NoncryptedBlob is a vanilla blob with no encryption data
// Despite appearnces, the MediaType type is not indicative of whether
// the blob is compressed or not
type NoncryptedBlob struct {
	MediaType string        `json:"mediaType"`
	Size      int64         `json:"size"`
	Digest    digest.Digest `json:"digest"`
	Filename  string        `json:"-"`
}

// GetDigest returnts the digest
func (b *NoncryptedBlob) GetDigest() digest.Digest { return b.Digest }

//GetMediaType returns the content type
func (b *NoncryptedBlob) GetMediaType() string { return b.MediaType }

// GetSize returns the size
func (b *NoncryptedBlob) GetSize() int64 { return b.Size }

// SetFilename set the filename of the file that the blob is stored in
func (b *NoncryptedBlob) SetFilename(filename string) { b.Filename = filename }

// GetFilename retun the filename of the file that the blob is stored in
func (b *NoncryptedBlob) GetFilename() string { return b.Filename }

// ReadCloser opens the file that backs the blob and returns a handle to it
// It is the user's responsibility to close the file handle
func (b *NoncryptedBlob) ReadCloser() (io.ReadCloser, error) { return os.Open(b.Filename) }

func newPlainBlob(
	filename string,
	d digest.Digest,
	size int64,
	mediaType string,
) *NoncryptedBlob {
	return &NoncryptedBlob{
		Size:      size,
		Digest:    d,
		MediaType: mediaType,
		Filename:  filename,
	}
}

// NewConfig creates a new blob for a config
func NewConfig(
	filename string,
	d digest.Digest,
	size int64,
	dec *crypto.DeCrypto,
) DecryptedBlob {
	return &decryptedConfig{
		NoncryptedBlob: newPlainBlob(filename, d, size, MediaTypeImageConfig),
		DeCrypto:       dec,
	}
}

// NewLayer creates a new LayerJSON for a data layer
func NewLayer(
	filename string,
	d digest.Digest,
	size int64,
	dec *crypto.DeCrypto,
) DecryptedBlob {
	return &decryptedBlob{
		NoncryptedBlob: newPlainBlob(filename, d, size, MediaTypeLayer),
		DeCrypto:       dec,
	}
}

// NewPlainLayer creates a new LayerJSON for an unencrypted data layer
func NewPlainLayer(
	filename string,
	d digest.Digest,
	size int64,
) DecompressedBlob {
	return newPlainBlob(filename, d, size, MediaTypeLayer)
}

// NewPlainConfig creates a new LayerJSON for an unencrypted data layer
func NewPlainConfig(
	filename string,
	d digest.Digest,
	size int64,
) DecompressedBlob {
	return newPlainBlob(filename, d, size, MediaTypeImageConfig)
}
