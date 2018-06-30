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
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/uuid"
	digest "github.com/opencontainers/go-digest"
	tarinator "github.com/verybluebot/tarinator-go"

	"github.com/Senetas/crypto-cli/registry"
	"github.com/Senetas/crypto-cli/types"
	"github.com/Senetas/crypto-cli/utils"
)

const labelString = "LABEL com.senetas.crypto.enabled=true"

const (
	user       = "narthanaepa1"
	repo       = "narthanaepa1/my-alpine"
	tag        = "crypto"
	service    = "registry.docker.io"
	authServer = "auth.docker.io"
	saltBase   = "com.senetas.crypto/" + repo + "/" + tag
	configSalt = saltBase + "/config"
	layerSalt  = saltBase + "/layer%d"
)

var path = os.TempDir() + "/com.senetas.crypto/"

func assembleManifest(config *types.LayerJSON, layers []*types.LayerJSON) *types.ImageManifestJSON {
	return &types.ImageManifestJSON{
		SchemaVersion: 2,
		MediaType:     "application/vnd.docker.distribution.manifest.v2+json",
		Config:        config,
		Layers:        layers}
}

func EncryptImage(repotag string) (string, *types.ImageManifestJSON, error) {
	layers, img, err := getImgTarLayers(repotag)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		err = utils.CheckedClose(img)
	}()

	// output image
	imgName := uuid.New().String()
	imgFile := path + imgName + ".tar"

	if err = os.MkdirAll(path+imgName, 0755); err != nil {
		return "", nil, err
	}

	outFile, err := os.Create(imgFile)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		err = utils.CheckedClose(outFile)
	}()

	if _, err = io.Copy(outFile, img); err != nil {
		return "", nil, err
	}

	if err = outFile.Sync(); err != nil {
		return "", nil, err
	}

	go func() {
		if err := img.Close(); err != nil {
			log.Println(err)
		}
	}()

	if err = tarinator.UnTarinate(path+imgName, imgFile); err != nil {
		return "", nil, err
	}

	go func() {
		if err := os.Remove(imgFile); err != nil {
			log.Println(err)
		}
	}()

	layerSet := make(map[string]bool)
	for _, x := range layers {
		layerSet[x] = true
	}

	configData, layerData, err := findLayers(repotag, path+imgName, layerSet)
	if err != nil {
		return "", nil, err
	}

	manifest := assembleManifest(configData, layerData)

	pass := "hunter2"
	if err = manifest.Config.Crypto.Encrypt(pass, configSalt); err != nil {
		return "", nil, err
	}

	for i, l := range manifest.Layers {
		salt := fmt.Sprintf(layerSalt, i)
		if l.Crypto != nil {
			if err = l.Crypto.Encrypt(pass, salt); err != nil {
				return "", nil, err
			}
		}
	}

	return imgName, manifest, nil
}

func DecryptImage(manifest *types.ImageManifestJSON) error {
	pass := "hunter2"
	salt := saltBase + repo + "/" + tag + "/config"
	fmt.Println(salt)
	// decrypt config
	if err := manifest.Config.Crypto.Decrypt(pass, salt); err != nil {
		return err
	}
	return nil
}

// PushImage encrypts then pushes an image
func PushImage(repotag string) (err error) {
	imgName, mainfest, err := EncryptImage(repotag)
	if err != nil {
		return err
	}

	// Upload to registry
	if err = registry.PushImage(user, repo, tag, service, authServer, mainfest); err != nil {
		return err
	}

	// cleanup temporary files
	if err = os.RemoveAll(path + imgName); err != nil {
		return err
	}

	return nil
}

// PullImage pulls an image from the registry
func PullImage(repotag string) (err error) {
	token, err := registry.Authenticate(user, service, repo, authServer)
	if err != nil {
		return err
	}

	manifest, err := registry.PullManifest(user, repo, tag, token)
	if err != nil {
		return err
	}

	fmt.Printf("Obtaining config: %s\n", manifest.Config.Digest)
	d := digest.Digest(manifest.Config.Digest)
	manifest.Config.Filename, err = registry.PullFromDigest(user, repo, token, &d)
	if err != nil {
		return err
	}

	fmt.Println("Obtaining layers")
	for _, l := range manifest.Layers {
		d := digest.Digest(l.Digest)
		l.Filename, err = registry.PullFromDigest(user, repo, token, &d)
		if err != nil {
			return err
		}
	}

	return nil
}
