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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/docker/docker/client"
	"github.com/pkg/errors"
	tarinator "github.com/verybluebot/tarinator-go"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/registry"
	"github.com/Senetas/crypto-cli/types"
	"github.com/Senetas/crypto-cli/utils"
)

// TarFromManifest takes a manifest and a target label for the images and create a tarball
// that may be loaded with docker load. It downloads and decrypts the config and layers if necessary
func TarFromManifest(manifest *types.ImageManifestJSON, ref registry.NamedTaggedRepository, passphrase string, cryptotype crypto.EncAlgo) (tarball string, err error) {
	salt := fmt.Sprintf(configSalt, ref.Path(), ref.Tag())

	// decrypt config key
	if err = manifest.Config.Crypto.Decrypt(passphrase, salt, cryptotype); err != nil {
		return "", err
	}

	dir := filepath.Dir(manifest.Config.Filename)
	if err = os.MkdirAll(dir, 0755); err != nil {
		return "", errors.Wrapf(err, "dir name = %s", dir)
	}

	// decrypt config file
	if err = crypto.DecFile(manifest.Config.Filename, manifest.Config.Filename+".dec", manifest.Config.Crypto.DecKey); err != nil {
		return "", err
	}

	// decompress config file
	d, err := utils.Decompress(manifest.Config.Filename + ".dec")
	if err != nil {
		return "", err
	}

	newDir := filepath.Join(dir, "new")
	if err = os.MkdirAll(newDir, 0755); err != nil {
		return "", errors.Wrapf(err, "dir name = %s", newDir)
	}

	if err = os.Rename(manifest.Config.Filename+".dec.dec", filepath.Join(newDir, d.Hex()+".json")); err != nil {
		return "", errors.Wrapf(err, "could not rename %s to %s", manifest.Config.Filename+".dec.dec", filepath.Join(newDir, d.Hex()+".json"))
	}

	am := &types.ArchiveManifest{
		Config:   d.Hex() + ".json",
		RepoTags: []string{ref.Path() + ":" + ref.Tag()},
		Layers:   make([]string, len(manifest.Layers))}

	// decrypt keys and files for layers
	for i, l := range manifest.Layers {
		if l.Crypto != nil {
			salt := fmt.Sprintf(layerSalt, ref.Path(), ref.Tag(), i)
			if err = l.Crypto.Decrypt(passphrase, salt, cryptotype); err != nil {
				return "", err
			}
		}

		layerfilename := l.Filename

		// decrypt layer file
		if l.Crypto != nil {
			layerfilename = l.Filename + ".dec"
			if err = crypto.DecFile(l.Filename, layerfilename, l.Crypto.DecKey); err != nil {
				return "", err
			}
		}

		// decompress layer file
		d, err = utils.Decompress(layerfilename)
		if err != nil {
			return "", err
		}

		layerfilename = layerfilename + ".dec"
		layernewname := filepath.Join(newDir, d.Hex()+".tar")

		if err = os.Rename(layerfilename, layernewname); err != nil {
			return "", errors.Wrapf(err, "could not rename %s to %s", layerfilename, layernewname)
		}

		am.Layers[i] = d.Hex() + ".tar"
	}

	amJSON, err := json.Marshal([]*types.ArchiveManifest{am})
	if err != nil {
		return "", errors.Wrapf(err, "archive manifest = %v", am)
	}

	manifestfilename := filepath.Join(newDir, "manifest.json")
	amr := bytes.NewReader(amJSON)
	amFH, err := os.Create(manifestfilename)
	if err != nil {
		return "", errors.Wrapf(err, "filename = %s", manifestfilename)
	}

	if _, err = io.Copy(amFH, amr); err != nil {
		return "", errors.Wrap(err, "")
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
	ctx := context.Background()

	// TODO: fix hardcoded version/ check if necessary
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithVersion("1.37"))
	if err != nil {
		return errors.Wrapf(err, "could not load client: %v", client.FromEnv)
	}

	fh, err := os.Open(tarball)
	if err != nil {
		return errors.Wrapf(err, "error opening file: %s", tarball)
	}

	resp, err := cli.ImageLoad(ctx, fh, false)
	if err != nil {
		return errors.Wrapf(err, "error loading image tarball: %s", tarball)
	}
	if err = resp.Body.Close(); err != nil {
		return errors.Wrapf(err, "error closing response body: %v", resp)
	}

	return nil
}
