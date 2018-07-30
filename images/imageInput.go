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
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/docker/client"
	"github.com/pkg/errors"
	tarinator "github.com/verybluebot/tarinator-go"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/distribution"
)

// Manifest2Tar takes a manifest and a target label for the images and creates a tarball that may
// be loaded with docker load. It downloads and decrypts the config and layers if necessary
func Manifest2Tar(
	manifest *distribution.ImageManifest,
	ref auth.Scope,
	opts *crypto.Opts,
) (tarball string, err error) {
	dir := manifest.DirName

	newDir := filepath.Join(dir, "new")
	if err = os.MkdirAll(newDir, 0700); err != nil {
		return "", errors.Wrapf(err, "dir name = %s", newDir)
	}

	archiveManifest := &distribution.ArchiveManifest{
		Config:   filepath.Base(manifest.Config.GetFilename()),
		RepoTags: []string{ref.String()},
		Layers:   make([]string, len(manifest.Layers)),
	}

	for i, l := range manifest.Layers {
		archiveManifest.Layers[i] = filepath.Base(l.GetFilename())
	}

	manifestfile := filepath.Join(newDir, "manifest.json")
	amFH, err := os.Create(manifestfile)
	if err != nil {
		return "", errors.Wrapf(err, "filename = %s", manifestfile)
	}

	enc := json.NewEncoder(amFH)
	if err = enc.Encode(&[]*distribution.ArchiveManifest{archiveManifest}); err != nil {
		return "", errors.Wrapf(err, "%#v", archiveManifest)
	}

	path := filepath.Join(newDir, "*")
	files, err := filepath.Glob(path)
	if err != nil {
		return "", errors.Wrapf(err, "path = %s", path)
	}

	tarball = filepath.Join(dir, "new.tar")
	if err = tarinator.Tarinate(files, tarball); err != nil {
		return "", err
	}

	return tarball, nil
}

func importImage(tarball string) error {
	// TODO: fix hardcoded version/ check if necessary
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithVersion("1.37"))
	if err != nil {
		return errors.Wrapf(err, "could not load client: %v", client.FromEnv)
	}

	fh, err := os.Open(tarball)
	if err != nil {
		return errors.Wrapf(err, "error opening file: %s", tarball)
	}

	resp, err := cli.ImageLoad(context.Background(), fh, false)
	if err != nil {
		return errors.Wrapf(err, "error loading image tarball: %s", tarball)
	}
	if err = resp.Body.Close(); err != nil {
		return errors.Wrapf(err, "error closing response body: %v", resp)
	}

	return nil
}
