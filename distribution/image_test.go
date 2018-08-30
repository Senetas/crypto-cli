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
	"os"
	"path/filepath"
	"testing"

	"github.com/docker/distribution/reference"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/udhos/equalfile"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/distribution"
	"github.com/Senetas/crypto-cli/registry/names"
	"github.com/Senetas/crypto-cli/utils"
)

func TestImageEncryptDecrypt(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	dir := filepath.Join(os.TempDir(), "com.senetas.crypto", uuid.New().String())
	defer func() { assert.NoError((utils.CleanUp(dir, nil))) }()

	ref, err := reference.ParseNormalizedNamed("narthanaepa1/my-alpine:test")
	require.Nil(err)

	nTRep, err := names.CastToTagged(ref)
	require.Nil(err)

	passphrase := "hunter2"

	tests := []struct {
		ref        names.NamedTaggedRepository
		opts       *crypto.Opts
		passphrase string
	}{
		{nTRep, opts, passphrase},
		{nTRep, optsNone, ""},
		{nTRep, optsCompat, passphrase},
	}

	for _, test := range tests {
		test.opts.SetPassphrase(passphrase)

		manifest, err := distribution.NewManifest(test.ref, test.opts, dir)
		if !assert.NoError(err) {
			continue
		}

		emanifest, err := manifest.Encrypt(test.ref, test.opts)
		if !assert.NoError(err) {
			continue
		}

		dmanifest, err := emanifest.Decrypt(test.ref, test.opts)
		if !assert.NoError(err) {
			continue
		}

		assert.Nil(checkFiles(dmanifest, manifest))
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
