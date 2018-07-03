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

	"github.com/Senetas/crypto-cli/images"
)

func TestEncDecImage(t *testing.T) {
	imgName, manifest, err := images.EncryptImage("narthanaepa1/my-alpine:test")
	if err != nil {
		t.Fatal(err)
	}

	dir := os.TempDir()
	path := dir + "/com.senetas.crypto/" + imgName
	if err = os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err = os.RemoveAll(path); err != nil {
			t.Log(err)
		}
	}()

	t.Log(manifest)

	if _, err = images.DecryptImage(manifest); err != nil {
		t.Fatalf("%v\ne = %s", err, manifest.Config.Crypto)
	}
}
