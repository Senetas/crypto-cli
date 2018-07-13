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

	"github.com/docker/distribution/reference"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/images"
	"github.com/Senetas/crypto-cli/registry"
)

func TestEncDecImage(t *testing.T) {
	ref, err := reference.ParseNormalizedNamed("narthanaepa1/my-alpine:test")
	if err != nil {
		t.Fatal(err)
	}

	ref2, err := registry.ResolveNamed(ref)
	if err != nil {
		t.Fatal(err)
	}

	manifest, err := images.CreateManifest(ref2, "hunter2", crypto.Pbkdf2Aes256Gcm)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(manifest)

	if _, err = images.Manifest2Tar(manifest, ref2, "hunter2", crypto.Pbkdf2Aes256Gcm); err != nil {
		t.Fatalf("%v\ne = %s", err, manifest.Config.Crypto)
	}

	if err = os.RemoveAll(manifest.DirName); err != nil {
		t.Log(err)
	}
}
