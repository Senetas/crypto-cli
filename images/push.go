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
	//"fmt"
	"os"

	"github.com/docker/distribution/reference"

	cref "github.com/Senetas/crypto-cli/reference"
	"github.com/Senetas/crypto-cli/registry"
)

// PushImage encrypts then pushes an image
func PushImage(ref *reference.Named) (err error) {
	endpoint, err := cref.GetEndPoint(ref)
	if err != nil {
		return err
	}

	//fmt.Println(endpoint)

	manifest, err := CreateManifest(ref)
	if err != nil {
		return err
	}

	// Upload to registry
	if err = registry.PushImage(user, service, authServer, ref, manifest, endpoint); err != nil {
		return err
	}

	// cleanup temporary files
	if err = os.RemoveAll(manifest.DirName); err != nil {
		return err
	}

	return nil
}
