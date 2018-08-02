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
	"fmt"
	"io"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/registry/names"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
)

const (
	saltBase   = "com.senetas.crypto/%s/%s"
	configSalt = saltBase + "/config"
	layerSalt  = saltBase + "/layer%d"
)

// ImageManifest represents a docker image manifest schema v2.2
type ImageManifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        Blob   `json:"config"`
	Layers        []Blob `json:"layers"`
	DirName       string `json:"-"`
}

func unencryptedConfig(blob *NoncryptedBlob) (Blob, error) {
	digester := digest.Canonical.Digester()
	r, err := blob.ReadCloser()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	size, err := io.Copy(digester.Hash(), r)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	d := digester.Digest()
	return NewPlainConfig(blob.GetFilename(), &d, size), nil
}

func prepareConfig(config Blob, opts *crypto.Opts, ref names.NamedTaggedRepository) (Blob, error) {
	switch blob := config.(type) {
	case DecryptedBlob:
		log.Info().Msg("encrypting config")
		opts.Salt = fmt.Sprintf(configSalt, ref.Path(), ref.Tag())
		return blob.EncryptBlob(*opts, blob.GetFilename()+".aes")
	case *NoncryptedBlob:
		log.Info().Msgf("preparing config")
		return unencryptedConfig(blob)
	default:
	}
	return nil, errors.New("config is of wrong type")
}

// Encrypt an image, generating an image manifest suitable for upload to a repo
func (m *ImageManifest) Encrypt(
	ref names.NamedTaggedRepository,
	opts *crypto.Opts,
) (
	_ *ImageManifest,
	err error,
) {
	configBlob, err := prepareConfig(m.Config, opts, ref)
	if err != nil {
		return nil, err
	}

	layerBlobs := make([]Blob, len(m.Layers))
	for i, l := range m.Layers {
		switch blob := l.(type) {
		case DecryptedBlob:
			log.Info().Msgf("encrypting layer %d", i)
			opts.Salt = fmt.Sprintf(layerSalt, ref.Path(), ref.Tag(), i)
			layerBlobs[i], err = blob.EncryptBlob(*opts, blob.GetFilename()+".aes")
		case *NoncryptedBlob:
			log.Info().Msgf("compressing layer %d", i)
			layerBlobs[i], err = blob.Compress(blob.GetFilename() + ".gz")
		default:
		}
		if err != nil {
			return nil, err
		}
	}

	return &ImageManifest{
		SchemaVersion: m.SchemaVersion,
		MediaType:     m.MediaType,
		DirName:       m.DirName,
		Config:        configBlob,
		Layers:        layerBlobs,
	}, nil
}

// DecryptKeys attempts to decrypt all keys in a manifest
func (m *ImageManifest) DecryptKeys(
	opts *crypto.Opts,
	ref names.NamedTaggedRepository,
) (err error) {
	switch blob := m.Config.(type) {
	case EncryptedBlob:
		opts.Salt = fmt.Sprintf(configSalt, ref.Path(), ref.Tag())
		m.Config, err = blob.DecryptKey(*opts)
		if err != nil {
			return err
		}
	case *NoncryptedBlob:
	default:
		return errors.New("mainfest blobs are of wrong type")
	}

	for i, l := range m.Layers {
		switch blob := l.(type) {
		case EncryptedBlob:
			opts.Salt = fmt.Sprintf(layerSalt, ref.Path(), ref.Tag(), i)
			m.Layers[i], err = blob.DecryptKey(*opts)
			if err != nil {
				return err
			}
		case *NoncryptedBlob:
		default:
			return errors.New("mainfest blobs are of wrong type")
		}
	}
	return nil
}

// DecryptManifest attempts to decrypt a manifest
// sending to manOut. It will call cancel on error.
func DecryptManifest(
	opts *crypto.Opts,
	ref names.NamedTaggedRepository,
	manifest *ImageManifest,
) (_ *ImageManifest, err error) {
	var config Blob
	switch blob := manifest.Config.(type) {
	case KeyDecryptedBlob:
		opts.Salt = fmt.Sprintf(configSalt, ref.Path(), ref.Tag())
		config, err = blob.DecryptFile(*opts, blob.GetFilename()+".dec")
	case *NoncryptedBlob:
		config = blob
	default:
		err = errors.Errorf("manifest is not decryptable: %#v", blob)
	}
	if err != nil {
		return nil, err
	}

	// decrypt keys and files for layers
	layers := make([]Blob, len(manifest.Layers))
	for i, l := range manifest.Layers {
		switch blob := l.(type) {
		case KeyDecryptedBlob:
			opts.Salt = fmt.Sprintf(layerSalt, ref.Path(), ref.Tag(), i)
			layers[i], err = blob.DecryptFile(*opts, blob.GetFilename()+".dec")
		case CompressedBlob:
			layers[i], err = blob.Decompress(blob.GetFilename() + ".dec")
		default:
		}
		if err != nil {
			return nil, err
		}
	}

	return &ImageManifest{
		SchemaVersion: manifest.SchemaVersion,
		MediaType:     manifest.MediaType,
		Config:        config,
		Layers:        layers,
		DirName:       manifest.DirName,
	}, nil
}
