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
	"github.com/docker/distribution/registry/client/auth"
	dregistry "github.com/docker/docker/registry"
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/distribution"
	"github.com/Senetas/crypto-cli/registry"
	"github.com/Senetas/crypto-cli/registry/names"
)

// PullImage pulls an image from the registry
func PullImage(ref reference.Named, opts *crypto.Opts) (err error) {
	token, nTRep, endpoint, err := authProcedure(ref)
	if err != nil {
		return
	}

	dir := filepath.Join(tempRoot, uuid.New().String())

	err = os.MkdirAll(dir, 0700)
	defer func() { err = cleanup(dir, err) }()
	if err != nil {
		return errors.Wrapf(err, "dir = %s", dir)
	}

	manifest, err := pullAndDecrypt(nTRep, token, endpoint, dir, opts)
	if err != nil {
		return
	}

	err = constructImageArchive(manifest, nTRep, opts)
	if err != nil {
		return
	}

	return
}

func pullAndDecrypt(
	nTRep names.NamedTaggedRepository,
	token auth.Scope,
	endpoint *dregistry.APIEndpoint,
	dir string,
	opts *crypto.Opts,
) (
	manifest *distribution.ImageManifest,
	err error,
) {
	manifest, err = registry.PullImage(token, nTRep, endpoint, opts, dir)
	if err != nil {
		return
	}
	return distribution.DecryptManifest(opts, nTRep, manifest)
}
