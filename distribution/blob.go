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
	ReadCloser() (io.ReadCloser, error)
}

// EncryptedBlob is a blob that may be decrypted
type EncryptedBlob interface {
	Blob
	// DecryptBlob decrypts:
	//     The Key encryption key contained in the "EnCrypto" struct
	//     The data stream in the FileHandle io.Reader
	// The data is also decompressed and written to a file which is referenced
	// in the "Filename"
	DecryptBlob(opts crypto.Opts, outfile string) (DecryptedBlob, error)
	DecryptKey(opts crypto.Opts) (KeyDecryptedBlob, error)
}

// KeyDecryptedBlob is a type for blobs that have had their key objects
// decrypted but not their files
type KeyDecryptedBlob interface {
	Blob
	DecryptFile(outfile string) (DecryptedBlob, error)
	EncryptKey(opts crypto.Opts) (EncryptedBlob, error)
}

// DecryptedBlob is a blob that may be encrypted
type DecryptedBlob interface {
	Blob
	// EncryptBlob compresses the blob file and encryptes
	//     The Key encryption key contained in the "DeCrypto" struct
	//     The data stream in the FileHandle io.Reader
	EncryptBlob(opts crypto.Opts, outfile string) (EncryptedBlob, error)
}

// CompressedBlob is a blob that may be decompressed
type CompressedBlob interface {
	Blob
	Decompress(outfile string) (DecompressedBlob, error)
}

// DecompressedBlob is a blob that may be compressed
type DecompressedBlob interface {
	Blob
	Compress(outfile string) (CompressedBlob, error)
}

// EncryptedBlob is the go type for an encrypted element in the layer array
type encryptedBlobNew struct {
	*NoncryptedBlob
	*EnCrypto `json:"crypto"`
}

// EncryptedBlob is the go type for an encrypted element in the layer array
type encryptedBlobCompat struct {
	*NoncryptedBlob
	URLs []string `json:"urls"`
}

type keyDecryptedBlob struct {
	*NoncryptedBlob
	*DeCrypto `json:"-"`
}

// DecryptedBlob is the go type for encryptable element in the layer array
type decryptedBlob struct {
	*NoncryptedBlob
	*DeCrypto `json:"-"`
}

// NoncryptedBlob is a vanilla blob with no encrpytion data
// Despite appearnces, the ContentType type is not indicative of whether
// the blob is compressed or not
type NoncryptedBlob struct {
	ContentType string         `json:"mediaType"`
	Size        int64          `json:"size"`
	Digest      *digest.Digest `json:"digest"`
	Filename    string         `json:"-"`
}

// GetDigest returnts the digest
func (b *NoncryptedBlob) GetDigest() *digest.Digest { return b.Digest }

//GetContentType returns the content type
func (b *NoncryptedBlob) GetContentType() string { return b.ContentType }

// GetSize returns the size
func (b *NoncryptedBlob) GetSize() int64 { return b.Size }

// SetFilename set the filename of the file that the blob is stored in
func (b *NoncryptedBlob) SetFilename(filename string) { b.Filename = filename }

// GetFilename retunrs the filename of the file that the blob is stored in
func (b *NoncryptedBlob) GetFilename() string { return b.Filename }

// ReadCloser opens the file that back the blob and returns a handle to it
// It is the user's responsibility to close the file handle
func (b *NoncryptedBlob) ReadCloser() (io.ReadCloser, error) { return os.Open(b.Filename) }

func newPlainBlob(
	filename string,
	d *digest.Digest,
	size int64,
	contentType string,
) *NoncryptedBlob {
	return &NoncryptedBlob{
		Size:        size,
		Digest:      d,
		ContentType: contentType,
		Filename:    filename,
	}
}

func newDecryptedBlob(
	filename string,
	d *digest.Digest,
	size int64,
	contentType string,
	dec *DeCrypto,
) *decryptedBlob {
	return &decryptedBlob{
		NoncryptedBlob: newPlainBlob(filename, d, size, contentType),
		DeCrypto:       dec,
	}
}

// NewPlainConfigBlob creates a new unencrypted blob for a config
func NewPlainConfigBlob(
	filename string,
	d *digest.Digest,
	size int64,
) DecompressedBlob {
	return newPlainBlob(filename, d, size, MediaTypeImageConfig)
}

// NewConfigBlob creates a new encrypted blob for a config
func NewConfigBlob(
	filename string,
	d *digest.Digest,
	size int64,
	dec *DeCrypto,
) DecryptedBlob {
	return newDecryptedBlob(filename, d, size, MediaTypeImageConfig, dec)
}

// NewLayerBlob creates a new LayerJSON for a data layer
func NewLayerBlob(
	filename string,
	d *digest.Digest,
	size int64,
	dec *DeCrypto,
) DecryptedBlob {
	return newDecryptedBlob(filename, d, size, MediaTypeLayer, dec)
}

// NewPlainLayer creates a new LayerJSON for an unencrypted data layer
func NewPlainLayer(
	filename string,
	d *digest.Digest,
	size int64,
) DecompressedBlob {
	blob := newPlainBlob(filename, d, size, MediaTypeLayer)
	return blob
}
