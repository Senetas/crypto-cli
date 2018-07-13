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
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/client"
	"github.com/google/uuid"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	tarinator "github.com/verybluebot/tarinator-go"

	"github.com/Senetas/crypto-cli/crypto"
	"github.com/Senetas/crypto-cli/distribution"
	"github.com/Senetas/crypto-cli/registry"
	"github.com/Senetas/crypto-cli/utils"
)

// CreateManifest creates a manifest and encrypts all necessary parts of it
// These are they ready to be uploaded to a regitry
func CreateManifest(
	ref registry.NamedTaggedRepository,
	passphrase string,
	cryptotype crypto.EncAlgo,
) (manifest *distribution.ImageManifest, err error) {
	layers, tarFH, err := getImgTarLayers(ref.Path(), ref.Tag())
	if err != nil {
		return nil, err
	}
	defer func() { err = utils.CheckedClose(tarFH, err) }()

	// output image
	manifest = &distribution.ImageManifest{
		SchemaVersion: 2,
		MediaType:     "application/vnd.docker.distribution.manifest.v2+json",
		DirName:       filepath.Join(tempRoot, uuid.New().String()),
	}

	// extract image
	if err = extractTarBall(tarFH, manifest); err != nil {
		return nil, err
	}

	configData, layerData, err := findLayers(ref.Path(), ref.Tag(), manifest.DirName, layers)
	if err != nil {
		return nil, err
	}

	manifest.Config = configData
	manifest.Layers = layerData

	salt := fmt.Sprintf(configSalt, ref.Path(), ref.Tag())

	if err = manifest.Config.Crypto.Encrypt(passphrase, salt, cryptotype); err != nil {
		return nil, err
	}

	for i, l := range manifest.Layers {
		salt = fmt.Sprintf(layerSalt, ref.Path(), ref.Tag(), i)
		if l.Crypto != nil {
			if err = l.Crypto.Encrypt(passphrase, salt, cryptotype); err != nil {
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
		return nil, nil, utils.StripTrace(errors.Wrap(err, "could not create client for docker daemon"))
	}

	// get the history
	hist, err := cli.ImageHistory(ctx, repo+":"+tag)
	if err != nil {
		return nil, nil, utils.StripTrace(err)
	}

	// obtain the most recent two complete images
	ids := []string{hist[0].ID}

	// advance pointer to history entry for LABEL "com.senetas.crypto.enabled=true"
	i := 0
	for ; i < len(hist) && !strings.Contains(hist[i].CreatedBy, labelString); i++ {
	}
	if i >= len(hist)-1 {
		return nil, nil, utils.NewError("no "+labelString+" in Dockerfile", false)
	}
	if hist[i+1].ID == "<missing>" {
		return nil, nil, utils.NewError("image not built on this Machine", false)
	}
	ids = append(ids, hist[i+1].ID)

	// map the layers of the two tags, since one tag was based on the other,
	// the layers of the lower tag should be duplicates of the upper one
	layerMap := make(map[string]int)
	for _, x := range ids {
		inspt, _, err := cli.ImageInspectWithRaw(ctx, x)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "inspecting layer %v", x)
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
		return nil, nil, errors.Wrap(err, "")
	}

	img, err := cli.ImageSave(ctx, []string{inspt.ID})
	if err != nil {
		return nil, nil, errors.Wrap(err, "")
	}

	return layers, img, nil
}

func extractTarBall(tarFH io.Reader, manifest *distribution.ImageManifest) (err error) {
	tarfile := manifest.DirName + ".tar"

	if err = os.MkdirAll(manifest.DirName, 0755); err != nil {
		return errors.Wrapf(err, "could not create: %s", manifest.DirName)
	}

	outFH, err := os.Create(tarfile)
	if err != nil {
		return errors.Wrapf(err, "could not create: %s", tarfile)
	}
	defer func() { err = utils.CheckedClose(outFH, err) }()

	if _, err = io.Copy(outFH, tarFH); err != nil {
		return errors.Wrapf(err, "could not extract to %s", tarfile)
	}

	if err = outFH.Sync(); err != nil {
		return errors.Wrapf(err, "could not sync file: %s", tarfile)
	}

	if err = tarinator.UnTarinate(manifest.DirName, tarfile); err != nil {
		return err
	}

	return nil
}

// find the layer files that correponds to the digests we want to encrypt
// TODO: find a way to do this by interfacing with the daemon directly
func findLayers(repo, tag, path string, layers []string) (*distribution.Layer, []*distribution.Layer, error) {
	// assemble layers
	layerSet := make(map[string]bool)
	for _, x := range layers {
		layerSet[x] = true
	}

	log.Debug().Msgf("layerSet = %+v", layerSet)

	// read the archive manifest
	manifestfile := filepath.Join(path, "manifest.json")
	dat, err := ioutil.ReadFile(manifestfile)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "could not open file: %s", manifestfile)
	}

	type configLayers struct {
		Config string
		Layers []string
	}

	var images []*configLayers
	if err := json.Unmarshal(dat, &images); err != nil {
		return nil, nil, errors.Wrapf(err, "error unmarshalling: %s", dat)
	}

	if len(images) < 1 {
		return nil, nil, errors.New("no image data was found")
	}

	configfile := filepath.Join(path, images[0].Config)
	filename, d, size, key, err := encryptLayer(configfile)
	if err != nil {
		return nil, nil, err
	}

	config := distribution.NewConfig(filename, d, size, key)

	layerJSON := make([]*distribution.Layer, len(images[0].Layers))
	for i, f := range images[0].Layers {
		basename := filepath.Join(path, f)

		fh, err := os.Open(basename)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "could not open file: %s", basename)
		}

		d, err := digest.Canonical.FromReader(fh)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "could not calculate digest: %s", basename)
		}

		log.Debug().Msgf("diffID = %s", d.String())

		if layerSet[d.String()] {
			log.Debug().Msgf("encrypting %s", d)
			filename, d, size, key, err := encryptLayer(basename)
			if err != nil {
				return nil, nil, err
			}
			layerJSON[i] = distribution.NewLayer(filename, d, size, key)
		} else {
			filename, d, size, _, err := compressLayer(basename)
			if err != nil {
				return nil, nil, err
			}
			layerJSON[i] = distribution.NewPlainLayer(filename, d, size)
		}
	}

	return config, layerJSON, nil
}

func compressLayer(filename string) (compFile string, d *digest.Digest, size int64, key []byte, err error) {
	compFile = filename + ".gz"

	d, err = utils.CompressWithDigest(filename)
	if err != nil {
		return "", nil, 0, nil, err
	}

	stat, err := os.Stat(compFile)
	if err != nil {
		return "", nil, 0, nil, errors.Wrapf(err, "could not stat file: %s", compFile)
	}

	return compFile, d, stat.Size(), key, nil
}

func encryptLayer(filename string) (encname string, d *digest.Digest, size int64, key []byte, err error) {
	compname := filename + ".gz"
	encname = compname + ".aes"

	if err := utils.Compress(filename); err != nil {
		return "", nil, 0, nil, err
	}

	key, err = crypto.GenDataKey()
	if err != nil {
		return "", nil, 0, nil, err
	}

	d, size, err = crypto.EncFile(compname, encname, key)
	if err != nil {
		return "", nil, 0, nil, err
	}

	return encname, d, size, key, nil
}
