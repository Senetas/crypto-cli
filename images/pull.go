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
	"github.com/google/uuid"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/distribution"
	"github.com/Senetas/crypto-cli/registry"
	"github.com/Senetas/crypto-cli/utils"
)

// PullImage pulls an image from the registry
func PullImage(ref reference.Named, passphrase string, cryptotype crypto.EncAlgo) (err error) {
	token, nTRep, endpoint, err := authProcedure(ref)
	if err != nil {
		return err
	}

	dir := filepath.Join(tempRoot, uuid.New().String())
	if err = os.MkdirAll(dir, 0755); err != nil {
		return errors.Wrapf(err, "dir = %s", dir)
	}
	defer cleanup(dir, err)

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

	go DecryptManifest(cancel, manChan, *nTRep, passphrase, cryptotype, manChan2, errChan2)
	go registry.PullImage(ctx, token, *nTRep, endpoint, dir, errChan2, manChan, errChan)

	errs := make(utils.Errors, 0)
	for i := 0; i < 2; {
		select {
		case err2 := <-errChan:
			errs = append(errs, err2)
			i++
		case err2 := <-errChan2:
			errs = append(errs, err2)
			i++
		default:
		}
	}
	if len(errs) != 0 {
		return errs
	}

	manifest := <-manChan2

	tarball, err := Manifest2Tar(manifest, *nTRep, passphrase, cryptotype)
	if err != nil {
		return err
	}

	if err = importImage(tarball); err != nil {
		return err
	}

	return nil
}

// cleanup temporary files
func cleanup(dir string, err error) error {
	if dir == "" {
		return err
	}
	if err2 := os.RemoveAll(dir); err2 != nil {
		err2 = errors.Wrapf(err, "could not clean up temp files in: %s", dir)
		if err == nil {
			return err2
		}
		return utils.Errors{err, err2}
	}
	return err
}
