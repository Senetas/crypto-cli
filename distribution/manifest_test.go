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

package distribution_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/distribution/reference"
	"github.com/google/uuid"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/udhos/equalfile"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/distribution"
	"github.com/Senetas/crypto-cli/registry/names"
	"github.com/Senetas/crypto-cli/utils"
)

const imageName = "cryptocli/alpine:latest"

type mockBlob byte

func (b *mockBlob) GetMediaType() string               { return "" }
func (b *mockBlob) GetDigest() digest.Digest           { return digest.Canonical.FromString("") }
func (b *mockBlob) GetSize() int64                     { return 0 }
func (b *mockBlob) GetFilename() string                { return "" }
func (b *mockBlob) SetFilename(f string)               {}
func (b *mockBlob) ReadCloser() (io.ReadCloser, error) { return nil, nil }

func TestImageMock(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	dir := filepath.Join(os.TempDir(), "com.senetas.crypto", uuid.New().String())
	defer func() { assert.NoError((utils.CleanUp(dir, nil))) }()

	ref, err := reference.ParseNormalizedNamed(imageName)
	require.NoError(err)

	nTRep, err := names.CastToTagged(ref)
	require.NoError(err)

	manifest, err := distribution.NewManifest(nTRep, opts, dir)
	require.NoError(err)

	mockConfig := &distribution.ImageManifest{
		SchemaVersion: 0,
		MediaType:     "",
		Config:        new(mockBlob),
		Layers:        []distribution.Blob{new(mockBlob)},
		DirName:       "",
	}
	_ = mockConfig

	mockLayer := &distribution.ImageManifest{
		SchemaVersion: 0,
		MediaType:     "",
		Config:        manifest.Config,
		Layers:        []distribution.Blob{new(mockBlob)},
		DirName:       "",
	}

	tests := []struct {
		manifest   *distribution.ImageManifest
		opts       crypto.Opts
		passphrase string
		errMsgEnc  string
		errMsgDec1 string
		errMsgDec2 string
	}{
		{
			mockConfig,
			*opts,
			passphrase,
			fmt.Sprintf("config is of wrong type: %T", new(mockBlob)),
			fmt.Sprintf("config is of wrong type: %T", new(mockBlob)),
			fmt.Sprintf("layer is of wrong type: %T", new(mockBlob)),
		},
		{
			mockLayer,
			*opts,
			passphrase,
			"",
			fmt.Sprintf("config is of wrong type: %T", manifest.Config),
			fmt.Sprintf("layer is of wrong type: %T", new(mockBlob)),
		},
	}

	for _, test := range tests {
		test.opts.SetPassphrase(test.passphrase)

		if _, err = test.manifest.Encrypt(nTRep, &test.opts); err != nil {
			assert.EqualError(err, test.errMsgEnc)
		}

		err = test.manifest.DecryptKeys(nTRep, &test.opts)
		assert.EqualError(err, test.errMsgDec1)

		_, err = test.manifest.Decrypt(nTRep, &test.opts)
		assert.EqualError(err, test.errMsgDec1)

		emanifest, err := manifest.Encrypt(nTRep, &test.opts)
		if !assert.NoError(err) {
			continue
		}

		emanifest.Layers = test.manifest.Layers

		err = emanifest.DecryptKeys(nTRep, &test.opts)
		assert.EqualError(err, test.errMsgDec2)

		_, err = emanifest.Decrypt(nTRep, &test.opts)
		assert.EqualError(err, test.errMsgDec2)
	}
}

func TestImageArchiveManifest(t *testing.T) {
	require := require.New(t)

	imageArchiveJSON := []byte(`[]`)
	b := bytes.NewReader(imageArchiveJSON)

	_, err := distribution.NewImageArchiveManifest(b)
	require.EqualError(err, "no image data was found")
}

func TestImageEncryptDecrypt(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	dir := filepath.Join(os.TempDir(), "com.senetas.crypto", uuid.New().String())
	defer func() { assert.NoError((utils.CleanUp(dir, nil))) }()

	ref, err := reference.ParseNormalizedNamed(imageName)
	require.NoError(err)

	nTRep, err := names.CastToTagged(ref)
	require.NoError(err)

	refNoEnc, err := reference.ParseNormalizedNamed("alpine:latest")
	require.NoError(err)

	nTRepNoEnc, err := names.CastToTagged(refNoEnc)
	require.NoError(err)

	tests := []struct {
		ref         names.NamedTaggedRepository
		opts        *crypto.Opts
		passphrase  string
		errMsg      string
		decryptKeys bool
	}{
		{nTRep, optsMock, passphrase, "mock is not a valid encryption type", false},
		{nTRepNoEnc, opts, passphrase, "this image was not built with the correct LABEL", false},
		{nTRep, opts, passphrase, "", true},
		{nTRep, optsNone, "", "", true},
		{nTRep, optsCompat, passphrase, "", true},
		{nTRep, opts, passphrase, "", false},
		{nTRep, optsNone, "", "", false},
		{nTRep, optsCompat, passphrase, "", false},
	}

	for _, test := range tests {
		test.opts.SetPassphrase(test.passphrase)

		manifest, err := distribution.NewManifest(test.ref, test.opts, dir)
		if err != nil && assert.EqualError(err, test.errMsg) || !assert.Equal(test.errMsg, "") {
			continue
		}

		emanifest, err := manifest.Encrypt(test.ref, test.opts)
		if !assert.NoError(err) {
			continue
		}

		if test.decryptKeys {
			if !assert.NoError(emanifest.DecryptKeys(test.ref, test.opts)) {
				continue
			}
		}

		dmanifest, err := emanifest.Decrypt(test.ref, test.opts)
		if !assert.NoError(err) {
			continue
		}

		assert.NoError(checkFiles(dmanifest, manifest))
	}
}

func checkFiles(m1, m2 *distribution.ImageManifest) (err error) {
	equal, err := equalfile.CompareFile(m1.Config.GetFilename(), m2.Config.GetFilename())
	if err != nil {
		return
	} else if !equal {
		return errors.New("configs not equal")
	}

	if len(m1.Layers) != len(m2.Layers) {
		return errors.New("differing number of layers")
	}

	for i, l := range m1.Layers {
		equal, err = equalfile.CompareFile(l.GetFilename(), m2.Layers[i].GetFilename())
		if err != nil {
			return
		} else if !equal {
			return errors.Errorf("layer %d not equal", i)
		}
	}

	return
}
