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
	"io"

	"github.com/minio/sio"
	"github.com/pkg/errors"
)

var defaultConfig = sio.Config{
	MinVersion:   sio.Version20,
	MaxVersion:   sio.Version20,
	CipherSuites: []byte{sio.AES_256_GCM},
}

// EncBlobWriter returns an io.WriteCloser that encrypts written data with
// the supplied key
func EncBlobWriter(in io.Writer, key []byte) (io.WriteCloser, error) {
	if len(key) != 32 {
		return nil, errors.New("key was of the wrong length")
	}

	cfg := defaultConfig
	cfg.Key = key

	return sio.EncryptWriter(in, cfg)
}

// DecBlobReader returns an io.Reader that decrypts reads with the supplied key
func DecBlobReader(in io.Reader, key []byte) (io.Reader, error) {
	if len(key) != 32 {
		return nil, errors.New("key was of the wrong length")
	}

	cfg := defaultConfig
	cfg.Key = key

	return sio.DecryptReader(in, cfg)
}
