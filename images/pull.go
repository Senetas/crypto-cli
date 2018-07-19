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
	"context"
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
	"github.com/Senetas/crypto-cli/utils"
)

// PullImage pulls an image from the registry
func PullImage(ref reference.Named, opts crypto.Opts) (err error) {
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

	return nil
}

func pullAndDecrypt(
	nTRep names.NamedTaggedRepository,
	token auth.Scope,
	endpoint *dregistry.APIEndpoint,
	dir string,
	opts crypto.Opts,
) (
	*distribution.ImageManifest,
	error,
) {
	ctx, cancel := context.WithCancel(context.Background())

	// TODO: make this more light weight and SAFE!
	manChan := make(chan *distribution.ImageManifest)
	manChan2 := make(chan *distribution.ImageManifest)
	errChan := make(chan error)
	errChan2 := make(chan error)
	defer close(manChan)
	defer close(manChan2)
	defer close(errChan)
	defer close(errChan2)

	go registry.PullImage(ctx, token, nTRep, endpoint, dir, manChan, errChan)
	go DecryptManifest(cancel, manChan, nTRep, opts, manChan2, errChan2)

	errs := make(utils.Errors, 0)
	var manifest *distribution.ImageManifest
	for i := 0; i < 3; {
		select {
		case err2 := <-errChan:
			if err2 != nil {
				errs = append(errs, err2)
			}
			i++
		case err2 := <-errChan2:
			if err2 != nil {
				errs = append(errs, err2)
			}
			i++
		case manifest = <-manChan2:
			i++
		default:
		}
	}

	if len(errs) != 0 {
		return nil, errs
	}

	return manifest, nil
}
