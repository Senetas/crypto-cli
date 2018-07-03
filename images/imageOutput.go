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
	"io"
	"io/ioutil"
	"strings"

	"github.com/docker/docker/client"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/types"
	"github.com/Senetas/crypto-cli/utils"
)

type localImageManifest struct {
	Config string
	Layers []string
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
	dat, err := ioutil.ReadFile(path + "/manifest.json")
	if err != nil {
		return nil, nil, err
	}

	var images []*localImageManifest
	if err := json.Unmarshal(dat, &images); err != nil {
		return nil, nil, err
	}

	if len(images) < 1 {
		return nil, nil, errors.New("no image data was found")
	}

	configfilename := path + "/" + images[0].Config
	filename, digest, size, key, err := encryptLayer(configfilename)
	if err != nil {
		return nil, nil, err
	}

	config := types.NewConfigJSON(filename, digest, size, key)

	layers := make([]*types.LayerJSON, len(images[0].Layers))
	for i, f := range images[0].Layers {
		basename := path + "/" + f
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
