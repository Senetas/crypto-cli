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

package images

import (
	"os"
	"path/filepath"

	"github.com/docker/distribution/reference"
	"github.com/google/uuid"
	spinner "github.com/janeczku/go-spinner"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/registry"
	"github.com/Senetas/crypto-cli/utils"
)

// PullImage pulls an image from the registry
func PullImage(ref reference.Named, opts *crypto.Opts, tempDir string) (err error) {
	token, nTRep, endpoint, err := authProcedure(ref)
	if err != nil {
		return
	}

	dir := filepath.Join(tempDir, uuid.New().String())

	err = os.MkdirAll(dir, 0700)
	defer func() { err = utils.CleanUp(dir, err) }()
	if err != nil {
		err = errors.Wrapf(err, "dir = %s", dir)
		return
	}

	emanifest, err := registry.PullImage(token, nTRep, endpoint, opts, dir)
	if err != nil {
		return
	}

	s := spinner.StartNew("Decrypting...")
	manifest, err := emanifest.Decrypt(nTRep, opts)
	if err != nil {
		return
	}
	s.Stop()

	return constructImageArchive(manifest, nTRep, opts)
}
