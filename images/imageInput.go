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
	tarinator "github.com/verybluebot/tarinator-go"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/registry"
	"github.com/Senetas/crypto-cli/types"
	"github.com/Senetas/crypto-cli/utils"
)

// TarFromManifest takes a manifest and a target label for the images and create a tarball
// that may be loaded with docker load. It downloads and decrypts the config and layers if necessary
func TarFromManifest(manifest *types.ImageManifestJSON, ref registry.NamedTaggedRepository) (tarball string, err error) {
	//repo, tag, err := cref.ResloveNamed(target)
	//if err != nil {
	//return "", err
	//}

	salt := fmt.Sprintf(configSalt, ref.Path(), ref.Tag())

	// decrypt config key
	if err := manifest.Config.Crypto.Decrypt(pass, salt); err != nil {
		return "", err
	}

	dir := filepath.Dir(manifest.Config.Filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	// decrypt config file
	if err := crypto.DecFile(manifest.Config.Filename, manifest.Config.Filename+".dec", manifest.Config.Crypto.DecKey); err != nil {
		return "", err
	}

	// decompress config file
	d, err := utils.Decompress(manifest.Config.Filename + ".dec")
	if err != nil {
		return "", err
	}

	newDir := filepath.Join(dir, "new")
	if err := os.MkdirAll(newDir, 0755); err != nil {
		return "", err
	}

	if err = os.Rename(manifest.Config.Filename+".dec.dec", filepath.Join(newDir, d.Hex()+".json")); err != nil {
		return "", err
	}

	am := &types.ArchiveManifest{
		Config:   d.Hex() + ".json",
		RepoTags: []string{ref.Path() + ":" + ref.Tag()},
		Layers:   make([]string, len(manifest.Layers))}

	// decrypt keys and files for layers
	for i, l := range manifest.Layers {
		if l.Crypto != nil {
			salt := fmt.Sprintf(layerSalt, ref.Path(), ref.Tag(), i)
			if err := l.Crypto.Decrypt(pass, salt); err != nil {
				return "", err
			}
		}

		layerfilename := l.Filename

		// decrypt layer file
		if l.Crypto != nil {
			layerfilename = l.Filename + ".dec"
			if err := crypto.DecFile(l.Filename, layerfilename, l.Crypto.DecKey); err != nil {
				return "", err
			}
		}

		// decompress layer file
		d, err := utils.Decompress(layerfilename)
		if err != nil {
			return "", err
		}

		layerfilename = layerfilename + ".dec"
		layernewname := filepath.Join(newDir, d.Hex()+".tar")

		if err = os.Rename(layerfilename, layernewname); err != nil {
			return "", err
		}

		am.Layers[i] = d.Hex() + ".tar"
	}

	amJSON, err := json.Marshal([]*types.ArchiveManifest{am})
	if err != nil {
		return "", err
	}

	amr := bytes.NewReader(amJSON)
	amFH, err := os.Create(filepath.Join(newDir, "manifest.json"))
	if err != nil {
		return "", err
	}

	if _, err = io.Copy(amFH, amr); err != nil {
		return "", err
	}

	files, err := filepath.Glob(filepath.Join(newDir, "*"))
	if err != nil {
		return "", err
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
		return err
	}

	fh, err := os.Open(tarball)
	if err != nil {
		return err
	}

	resp, err := cli.ImageLoad(ctx, fh, false)
	if err != nil {
		return err
	}
	resp.Body.Close()

	return nil
}
