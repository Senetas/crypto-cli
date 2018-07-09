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
	dockerregistry "github.com/docker/docker/registry"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/registry"
)

// PushImage encrypts then pushes an image
func PushImage(ref reference.Named) (err error) {
	nTRep, err := registry.ResolveNamed(ref)
	if err != nil {
		return err
	}

	repoInfo, err := dockerregistry.ParseRepositoryInfo(ref)
	if err != nil {
		return err
	}

	endpoint, err := registry.GetEndPoint(ref, *repoInfo)
	if err != nil {
		return err
	}

	token, err := registry.Authenticate(nTRep, *repoInfo, endpoint)
	if err != nil {
		return err
	}

	manifest, err := CreateManifest(nTRep)
	if err != nil {
		return err
	}

	// Upload to registry
	if err = registry.PushImage(token, nTRep, manifest, &endpoint); err != nil {
		return err
	}

	// cleanup temporary files
	if err = os.RemoveAll(manifest.DirName); err != nil {
		return errors.Wrap(err, "Warning: temporary files not removed!")
	}

	return nil
}
