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

	"github.com/docker/distribution/reference"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/registry"
)

// PushImage encrypts then pushes an image
func PushImage(ref reference.Named, opts crypto.Opts) (err error) {
	token, nTRep, endpoint, err := authProcedure(ref)
	if err != nil {
		return err
	}

	manifest, err := CreateManifest(nTRep, opts)
	if err != nil {
		return err
	}

	encManifest, err := manifest.Encrypt(nTRep, opts)
	if err != nil {
		return err
	}

	if err = registry.PushImage(token, nTRep, encManifest, endpoint); err != nil {
		return err
	}

	// cleanup temporary files
	if err = os.RemoveAll(manifest.DirName + ".tar"); err != nil {
		return errors.Wrapf(err, "could not clean up temp file: %s", manifest.DirName+".tar")
	}

	if err = os.RemoveAll(manifest.DirName); err != nil {
		return errors.Wrapf(err, "could not clean up temp files in: %s", manifest.DirName)
	}

	return nil
}
