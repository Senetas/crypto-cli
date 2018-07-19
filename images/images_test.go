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
	"context"
	"os"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/docker/distribution/reference"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/distribution"
	"github.com/Senetas/crypto-cli/images"
	"github.com/Senetas/crypto-cli/registry/names"
	"github.com/Senetas/crypto-cli/utils"
)

func prepareManifest(t *testing.T, opts crypto.Opts) (
	*distribution.ImageManifest,
	names.NamedTaggedRepository,
) {
	ref, err := reference.ParseNormalizedNamed("narthanaepa1/my-alpine:test")
	if err != nil {
		t.Fatal(err)
	}

	ref2, err := names.CastToTagged(ref)
	if err != nil {
		t.Fatal(err)
	}

	manifest, err := images.CreateManifest(ref2, opts)
	if err != nil {
		t.Fatal(err)
	}

	return manifest, ref2
}

func testEncDecImage(t *testing.T, opts crypto.Opts) {
	manifest, ref := prepareManifest(t, opts)

	t.Log(spew.Sdump(manifest))

	_, cancel := context.WithCancel(context.Background())

	manChan := make(chan *distribution.ImageManifest)
	manChan2 := make(chan *distribution.ImageManifest)
	errChan2 := make(chan error)

	defer close(manChan)
	defer close(manChan2)
	defer close(errChan2)

	go images.DecryptManifest(cancel, manChan, ref, opts, manChan2, errChan2)

	manChan <- manifest

	errs := make(utils.Errors, 0)
	for i := 0; i < 2; {
		select {
		case err2 := <-errChan2:
			if err2 != nil {
				errs = append(errs, err2)
			}
			i++
		case manifest = <-manChan2:
			i++
		default:
		}
	}

	if len(errs) != 0 {
		t.Fatal(errs)
	}

	t.Log(spew.Sdump(manifest))

	if _, err := images.Manifest2Tar(manifest, ref, opts); err != nil {
		t.Fatal(err)
	}

	if err := os.RemoveAll(manifest.DirName); err != nil {
		t.Log(err)
	}
}

func TestEncDecImage(t *testing.T) {
	opts := crypto.Opts{
		Passphrase: "hunter2",
		EncType:    crypto.Pbkdf2Aes256Gcm,
		Compat:     false,
	}
	t.Logf("testing non-compat")
	testEncDecImage(t, opts)
}

func TestCompatEncDecImage(t *testing.T) {
	opts := crypto.Opts{
		Passphrase: "hunter2",
		EncType:    crypto.Pbkdf2Aes256Gcm,
		Compat:     true,
	}
	t.Logf("testing compat")
	testEncDecImage(t, opts)
}
