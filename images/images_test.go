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

package images_test

import (
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/docker/distribution/reference"
	"github.com/udhos/equalfile"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/distribution"
	"github.com/Senetas/crypto-cli/images"
	"github.com/Senetas/crypto-cli/registry/names"
)

func createManifest(t *testing.T, opts *crypto.Opts) (
	*distribution.ImageManifest,
	names.NamedTaggedRepository,
) {
	ref, err := reference.ParseNormalizedNamed("narthanaepa1/my-alpine:test")
	if err != nil {
		t.Fatalf("%+v", err)
	}

	ref2, err := names.CastToTagged(ref)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	manifest, err := images.CreateManifest(ref2, opts)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	return manifest, ref2
}

// Todo, compare contents
func testEncDecImage(t *testing.T, opts *crypto.Opts) {
	manifest, ref := createManifest(t, opts)

	defer cleanUp(t, manifest)

	encManifest, err := manifest.Encrypt(ref, opts)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	t.Log(spew.Sdump(manifest))

	if err = encManifest.DecryptKeys(opts, ref); err != nil {
		t.Fatalf("%+v", err)
	}

	decManifest, err := distribution.DecryptManifest(opts, ref, encManifest)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	t.Log(spew.Sdump(manifest))

	equal, err := equalfile.CompareFile(manifest.Config.GetFilename(), decManifest.Config.GetFilename())
	if err != nil {
		t.Error(err)
	}
	if !equal {
		t.Error("files not equal")
	}

	for i, l := range manifest.Layers {
		equal, err := equalfile.CompareFile(l.GetFilename(), decManifest.Layers[i].GetFilename())
		if err != nil {
			t.Error(err)
		}
		if !equal {
			t.Error("files not equal")
		}
	}
}

func TestEncDecImage(t *testing.T) {
	opts := crypto.Opts{
		EncType: crypto.Pbkdf2Aes256Gcm,
		Compat:  false,
	}
	opts.SetPassphrase("hunter2")
	t.Logf("testing non-compat")
	testEncDecImage(t, &opts)
}

func TestCompatEncDecImage(t *testing.T) {
	opts := crypto.Opts{
		EncType: crypto.Pbkdf2Aes256Gcm,
		Compat:  true,
	}
	opts.SetPassphrase("hunter2")
	t.Logf("testing compat")
	testEncDecImage(t, &opts)
}

func cleanUp(t *testing.T, manifest *distribution.ImageManifest) {
	if err := os.RemoveAll(manifest.DirName); err != nil {
		t.Log(err)
	}

	if err := os.Remove(manifest.DirName + ".tar"); err != nil {
		t.Log(err)
	}
}
