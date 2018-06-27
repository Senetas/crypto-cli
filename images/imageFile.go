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
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Senetas/crypto-cli/utils"
)

type localImageManifest struct {
	Config string
	Layers []string
}

const saltBase = "com.senetas.crypto/"

func assembleManifest(config *LayerJSON, layers []*LayerJSON) *ImageManifestJSON {
	return &ImageManifestJSON{
		SchemaVersion: 2,
		MediaType:     "application/vnd.docker.distribution.manifest.v2+json",
		Config:        config,
		Layers:        layers}
}

// find the layer files that correpond to the digests we want to encrypt
// TODO: find a way to do this by interfacing with the daemon directly
func findLayers(imageID, path string, layerSet map[string]bool) (*LayerJSON, []*LayerJSON, error) {
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

	configFile := path + "/" + images[0].Config
	filename, digest, size, key, err := encryptLayer(configFile)
	if err != nil {
		return nil, nil, err
	}

	salt := saltBase + imageID + "/config"
	configJSON, err := NewLayerJSON(filename, digest, size, key, "hunter2", salt)
	if err != nil {
		return nil, nil, err
	}

	layers := make([]*LayerJSON, len(layerSet))
	for i, f := range images[0].Layers {
		basename := path + "/" + f
		sum, err := utils.Sha256sum(basename)
		if err != nil {
			return nil, nil, err
		}

		l := "sha256:" + sum
		var layerJSON *LayerJSON
		if layerSet[l] {
			filename, digest, size, key, err := encryptLayer(basename)
			if err != nil {
				return nil, nil, err
			}

			salt := saltBase + imageID + "/layer" + string(i)
			layerJSON, err = NewLayerJSON(filename, digest, size, key, "hunter2", salt)
			if err != nil {
				return nil, nil, err
			}
		} else {
			stats, err := os.Stat(basename)
			if err != nil {
				return nil, nil, err
			}

			layerJSON, err = NewPlainLayerJSON(basename, l, stats.Size())
			if err != nil {
				return nil, nil, err
			}
		}
		layers = append(layers, layerJSON)
		fmt.Println(layers)
	}

	return configJSON, layers, nil
}

func encryptLayer(filename string) (string, string, int64, []byte, error) {
	compFile := filename + ".gz"
	encFile := compFile + ".aes"

	if err := utils.Compress(filename); err != nil {
		return "", "", 0, nil, err
	}

	key, size, err := utils.EncFile(compFile, encFile)
	if err != nil {
		return "", "", 0, nil, err
	}

	sum, err := utils.Sha256sum(encFile)
	if err != nil {
		return "", "", 0, nil, err
	}
	digest := "sha256:" + sum

	return encFile, digest, size, key, nil
}
