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
	dockerregistry "github.com/docker/docker/registry"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/registry"
)

// PullImage pulls an image from the registry
func PullImage(ref reference.Named, passphrase string, cryptotype crypto.EncAlgo) (err error) {
	nTRep, err := registry.ResolveNamed(ref)
	if err != nil {
		return err
	}

	repoInfo, err := dockerregistry.ParseRepositoryInfo(ref)
	if err != nil {
		return errors.Wrapf(err, "could not parse ref = %v", ref)
	}

	endpoint, err := registry.GetEndPoint(ref, *repoInfo)
	if err != nil {
		return errors.Wrapf(err, "could not get endpoint ref = %v, repoInfo = %v", ref, *repoInfo)
	}

	token, err := registry.Authenticate(nTRep, *repoInfo, endpoint)
	if err != nil {
		return err
	}

	dir := filepath.Join(tempRoot, uuid.New().String())
	if err = os.MkdirAll(dir, 0755); err != nil {
		return errors.Wrapf(err, "dir = %s", dir)
	}

	manifest, err := registry.PullImage(token, nTRep, &endpoint, dir)
	if err != nil {
		return err
	}

	tarball, err := TarFromManifest(manifest, nTRep, passphrase, cryptotype)
	if err != nil {
		return err
	}

	if err = importImage(tarball); err != nil {
		return err
	}

	// cleanup temporary files
	if err = os.RemoveAll(dir); err != nil {
		return errors.Wrapf(err, "could not clean up temp files in: %s", dir)
	}

	return nil
}
