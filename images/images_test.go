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
		t.Error(err)
	}

	dir := os.TempDir()
	path := dir + "/com.senetas.crypto/" + imgName

	t.Log(path)
	t.Log(manifest.Config.Crypto)

	if err = images.DecryptImage(manifest); err != nil {
		t.Errorf("%v\ne = %s", err, manifest.Config.Crypto)
	}
}
