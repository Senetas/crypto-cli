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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/distribution/reference"
	"github.com/docker/docker/client"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	tarinator "github.com/verybluebot/tarinator-go"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/types"
	"github.com/Senetas/crypto-cli/utils"
)

// CreateManifest creates a manifest and encrypts all necessary parts of it
// These are they ready to be uploaded to a regitry
func CreateManifest(ref *reference.Named) (manifest *types.ImageManifestJSON, err error) {
	repo, tag, err := resloveNamed(ref)
	if err != nil {
		return nil, err
	}

	layers, img, err := getImgTarLayers(repo, tag)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = utils.CheckedClose(img, err)
	}()

	// output image
	manifest = &types.ImageManifestJSON{
		SchemaVersion: 2,
		MediaType:     "application/vnd.docker.distribution.manifest.v2+json",
		DirName:       path + uuid.New().String()}
	imgFile := manifest.DirName + ".tar"

	if err = os.MkdirAll(manifest.DirName, 0755); err != nil {
		return nil, err
	}

	outFile, err := os.Create(imgFile)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = utils.CheckedClose(outFile, err)
	}()

	if _, err = io.Copy(outFile, img); err != nil {
		return nil, err
	}

	if err = outFile.Sync(); err != nil {
		return nil, err
	}

	go func() {
		if err := img.Close(); err != nil {
			log.Error().Err(err)
		}
	}()

	if err = tarinator.UnTarinate(manifest.DirName, imgFile); err != nil {
		return nil, err
	}

	// delete source tarball
	go func() {
		if err := os.Remove(imgFile); err != nil {
			log.Error().Err(err)
		}
	}()

	layerSet := make(map[string]bool)
	for _, x := range layers {
		layerSet[x] = true
	}

	configData, layerData, err := findLayers(repo, tag, manifest.DirName, layerSet)
	if err != nil {
		return nil, err
	}

	manifest.Config = configData
	manifest.Layers = layerData

	pass := "hunter2"
	salt := fmt.Sprintf(configSalt, repo, tag)
	if err = manifest.Config.Crypto.Encrypt(pass, salt); err != nil {
		return nil, err
	}

	for i, l := range manifest.Layers {
		salt = fmt.Sprintf(layerSalt, repo, tag, i)
		if l.Crypto != nil {
			if err = l.Crypto.Encrypt(pass, salt); err != nil {
				return nil, err
			}
		}
	}

	return manifest, nil
}

func getImgTarLayers(repo, tag string) ([]string, io.ReadCloser, error) {
	ctx := context.Background()

	// TODO: fix hardcoded version/ check if necessary
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithVersion("1.37"))
	if err != nil {
		return nil, nil, err
	}

	// get the history
	hist, err := cli.ImageHistory(ctx, repo+":"+tag)
	if err != nil {
		return nil, nil, err
	}

	// obtain the most recent two complete images
	ids := []string{hist[0].ID}

	// advance pointer to history entry for LABEL "com.senetas.crypto.enabled=true"
	i := 0
	for ; i < len(hist) && !strings.Contains(hist[i].CreatedBy, labelString); i++ {
	}
	if i >= len(hist)-1 {
		return nil, nil, errors.New("no " + labelString + " in Dockerfile")
	}
	if hist[i+1].ID == "<missing>" {
		return nil, nil, errors.New("images not built on this Machine")
	}
	ids = append(ids, hist[i+1].ID)

	// map the layers of the two tags, since one tag was based on the other,
	// the layers of the lower tag should be duplicates of the upper one
	layerMap := make(map[string]int)
	for _, x := range ids {
		inspt, _, err := cli.ImageInspectWithRaw(ctx, x)
		if err != nil {
			return nil, nil, err
		}

		for _, x := range inspt.RootFS.Layers {
			layerMap[x]++
		}
	}

	layers := []string{}
	for k, v := range layerMap {
		if v == 1 {
			layers = append(layers, k)
		}
	}

	inspt, _, err := cli.ImageInspectWithRaw(ctx, repo+":"+tag)
	if err != nil {
		return nil, nil, err
	}

	img, err := cli.ImageSave(ctx, []string{inspt.ID})
	if err != nil {
		return nil, nil, err
	}

	return layers, img, nil
}

// find the layer files that correponds to the digests we want to encrypt
// TODO: find a way to do this by interfacing with the daemon directly
func findLayers(repo, tag, path string, layerSet map[string]bool) (*types.LayerJSON, []*types.LayerJSON, error) {
	dat, err := ioutil.ReadFile(filepath.Join(path, "manifest.json"))
	if err != nil {
		return nil, nil, err
	}

	type configLayers struct {
		Config string
		Layers []string
	}

	var images []*configLayers
	if err := json.Unmarshal(dat, &images); err != nil {
		return nil, nil, err
	}

	if len(images) < 1 {
		return nil, nil, errors.New("no image data was found")
	}

	configfilename := filepath.Join(path, images[0].Config)
	filename, digest, size, key, err := encryptLayer(configfilename)
	if err != nil {
		return nil, nil, err
	}

	config := types.NewConfigJSON(filename, digest, size, key)

	layers := make([]*types.LayerJSON, len(images[0].Layers))
	for i, f := range images[0].Layers {
		basename := filepath.Join(path, f)
		sum, err := crypto.Sha256sum(basename)
		if err != nil {
			return nil, nil, err
		}

		l := "sha256:" + sum
		if layerSet[l] {
			filename, digest, size, key, err := encryptLayer(basename)
			if err != nil {
				return nil, nil, err
			}
			layers[i] = types.NewLayerJSON(filename, digest, size, key)
		} else {
			filename, digest, size, _, err := compressLayer(basename)
			if err != nil {
				return nil, nil, err
			}
			layers[i] = types.NewPlainLayerJSON(filename, digest, size)
		}
	}

	return config, layers, nil
}

func compressLayer(filename string) (compFile string, dg string, size int64, key []byte, err error) {
	compFile = filename + ".gz"

	if err := utils.Compress(filename); err != nil {
		return "", "", 0, nil, err
	}

	stat, err := os.Stat(compFile)
	if err != nil {
		return "", "", 0, nil, err
	}

	size = stat.Size()

	sum, err := crypto.Sha256sum(compFile)
	if err != nil {
		return "", "", 0, nil, err
	}
	dg = "sha256:" + sum

	return compFile, dg, size, key, nil
}

func encryptLayer(filename string) (encFile string, dg string, size int64, key []byte, err error) {
	compFile := filename + ".gz"
	encFile = compFile + ".aes"

	if err := utils.Compress(filename); err != nil {
		return "", "", 0, nil, err
	}

	key, _, size, err = crypto.EncFile(compFile, encFile)
	if err != nil {
		return "", "", 0, nil, err
	}

	sum, err := crypto.Sha256sum(encFile)
	if err != nil {
		return "", "", 0, nil, err
	}
	dg = "sha256:" + sum

	return encFile, dg, size, key, nil
}
