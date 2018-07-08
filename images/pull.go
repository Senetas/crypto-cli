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

	"github.com/Senetas/crypto-cli/registry"
)

// PullImage pulls an image from the registry
func PullImage(ref reference.Named) (err error) {
	nTRep, err := registry.ResolveNamed(ref)
	if err != nil {
		return err
	}

	endpoint, err := registry.GetEndPoint(ref)
	if err != nil {
		return err
	}

	token, err := registry.Authenticate(user, service, authServer, nTRep)
	if err != nil {
		return err
	}

	manifest, err := registry.PullImage(token, nTRep, endpoint)
	if err != nil {
		return err
	}

	tarball, err := TarFromManifest(manifest, nTRep)
	if err != nil {
		return err
	}

	if err = importImage(tarball); err != nil {
		return err
	}

	// cleanup temporary files
	if err = os.RemoveAll(path); err != nil {
		return err
	}

	return nil
}
