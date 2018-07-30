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
	"github.com/rs/zerolog/log"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/distribution"
	"github.com/Senetas/crypto-cli/registry"
	"github.com/Senetas/crypto-cli/registry/names"
)

// PullImage pulls an image from the registry
func PullImage(ref reference.Named, opts *crypto.Opts) (err error) {
	token, nTRep, endpoint, err := authProcedure(ref)
	if err != nil {
		return err
	}

	dir := filepath.Join(tempRoot, uuid.New().String())
	if err = os.MkdirAll(dir, 0700); err != nil {
		return errors.Wrapf(err, "dir = %s", dir)
	}
	defer func() { err = cleanup(dir, err) }()

	manifest, err := pullAndDecrypt(nTRep, token, endpoint, dir, opts)
	if err != nil {
		return err
	}

	tarball, err := Manifest2Tar(manifest, nTRep, opts)
	if err != nil {
		return err
	}

	if err = importImage(tarball); err != nil {
		return err
	}

	log.Info().Msg("image pulled successfully")

	if err = os.RemoveAll(dir); err != nil {
		return errors.Wrapf(err, "could not remove temp files in: %s", dir)
	}

	return nil
}

func pullAndDecrypt(
	nTRep names.NamedTaggedRepository,
	token auth.Scope,
	endpoint *dregistry.APIEndpoint,
	dir string,
	opts *crypto.Opts,
) (
	*distribution.ImageManifest,
	error,
) {
	manifest, err := registry.PullImage(token, nTRep, endpoint, opts, dir)
	if err != nil {
		return nil, err
	}
	return distribution.DecryptManifest(manifest)
}
