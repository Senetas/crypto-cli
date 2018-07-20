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

	"github.com/Senetas/crypto-cli/crypto"
	digest "github.com/opencontainers/go-digest"
)

// Blob represents an entry for a blob in the image manifest
type Blob interface {
	GetContentType() string
	GetDigest() *digest.Digest
	GetSize() int64
	GetFilename() string
	SetFilename(filename string)
	//Reader() io.ReadCloser
	//Writer() io.WriteCloser
}

// EncryptedBlob is a blob that may be decrypted
type EncryptedBlob interface {
	Blob
	// DecryptBlob decrypts:
	//     The Key encryption key contained in the "EnCrypto" struct
	//     The data stream in the FileHandle io.Reader
	// The data is also decompressed and written to a file which is referenced in the "Filename"
	DecryptBlob(opts crypto.Opts, outfile string) (DecryptedBlob, error)
}

// DecryptedBlob is a blob that may be encrypted
type DecryptedBlob interface {
	Blob
	// EncryptBlob compresses the blob file and encryptes
	//     The Key encryption key contained in the "DeCrypto" struct
	//     The data stream in the FileHandle io.Reader
	EncryptBlob(opts crypto.Opts, outfile string) (EncryptedBlob, error)
}

type CompressedBlob interface {
	Blob
	Decompress(outfile string) (DecompressedBlob, error)
}

type DecompressedBlob interface {
	Blob
	Compress(outfile string) (CompressedBlob, error)
}

// EncryptedBlob is the go type for an encrypted element in the layer array
type encryptedBlobNew struct {
	*NoncryptedBlob
	*EnCrypto `json:"crypto,omitempty"`
}

// EncryptedBlob is the go type for an encrypted element in the layer array
type encryptedBlobCompat struct {
	*NoncryptedBlob
	URLs []string `json:"urls,omitempty"`
}

// DecryptedBlob is the go type for encryptable element in the layer array
type decryptedBlob struct {
	*NoncryptedBlob
	*DeCrypto `json:"-"`
}

type NoncryptedBlob struct {
	ContentType string         `json:"mediaType"`
	Size        int64          `json:"size"`
	Digest      *digest.Digest `json:"digest"`
	Filename    string         `json:"-"`
	FileHandle  io.ReadWriter  `json:"-"`
}

func (b *NoncryptedBlob) GetDigest() *digest.Digest { return b.Digest }

func (b *NoncryptedBlob) GetContentType() string { return b.ContentType }

func (b *NoncryptedBlob) GetSize() int64 { return b.Size }

func (b *NoncryptedBlob) SetFilename(filename string) { b.Filename = filename }

func (b *NoncryptedBlob) GetFilename() string { return b.Filename }

func newPlainBlob(
	filename string,
	filehandle io.ReadWriter,
	d *digest.Digest,
	size int64,
) *NoncryptedBlob {
	return &NoncryptedBlob{
		Size:       size,
		Digest:     d,
		Filename:   filename,
		FileHandle: filehandle,
	}
}

func newDecryptedBlob(
	filename string,
	filehandle io.ReadWriter,
	d *digest.Digest,
	size int64,
	contentType string,
	dec *DeCrypto,
) *decryptedBlob {
	return &decryptedBlob{
		NoncryptedBlob: newPlainBlob(filename, filehandle, d, size),
		DeCrypto:       dec,
	}
}

// NewConfigBlob creates a new Layer for a config layer
func NewConfigBlob(
	filename string,
	filehandle io.ReadWriter,
	d *digest.Digest,
	size int64,
	dec *DeCrypto,
) Blob {
	return newDecryptedBlob(filename, filehandle, d, size, MediaTypeImageConfig, dec)
}

// NewLayerBlob creates a new LayerJSON for a data layer
func NewLayerBlob(
	filename string,
	filehandle io.ReadWriter,
	d *digest.Digest,
	size int64,
	dec *DeCrypto,
) Blob {
	return newDecryptedBlob(filename, filehandle, d, size, MediaTypeLayer, dec)
}

// NewPlainLayer creates a new LayerJSON for an unencrypted data layer
func NewPlainLayer(
	filename string,
	filehandle io.ReadWriter,
	d *digest.Digest,
	size int64,
) Blob {
	blob := newPlainBlob(filename, filehandle, d, size)
	blob.ContentType = MediaTypeLayer
	return blob
}
