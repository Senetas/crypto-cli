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
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	digest "github.com/opencontainers/go-digest"
	tarinator "github.com/verybluebot/tarinator-go"

	"github.com/Senetas/crypto-cli/crypto"
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

func EncryptImage(repotag string) (imgName string, manifest *types.ImageManifestJSON, err error) {
	layers, img, err := getImgTarLayers(repotag)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		err = utils.CheckedClose(img, err)
	}()

	// output image
	imgName = uuid.New().String()
	imgFile := path + imgName + ".tar"

	if err = os.MkdirAll(path+imgName, 0755); err != nil {
		return "", nil, err
	}

	outFile, err := os.Create(imgFile)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		err = utils.CheckedClose(outFile, err)
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

	manifest = assembleManifest(configData, layerData)

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

func DecryptImage(manifest *types.ImageManifestJSON) (tarball string, err error) {
	pass := "hunter2"
	salt := configSalt

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
		RepoTags: []string{repo + ":" + tag},
		Layers:   make([]string, len(manifest.Layers))}

	for i, l := range manifest.Layers {
		if l.Crypto != nil {
			salt := fmt.Sprintf(layerSalt, i)
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

//func scanlChainID(diffIDs []layer.DiffID) []layer.ChainID {
//return scanlChainIDRec(make([]layer.ChainID, 0), diffIDs)
//}

//func scanlChainIDRec(ancestors []layer.ChainID, diffIDs []layer.DiffID) []layer.ChainID {
//if len(diffIDs) == 0 {
//return ancestors
//}
//if len(ancestors) == 0 {
//return scanlChainIDRec([]layer.ChainID{layer.ChainID(diffIDs[0])}, diffIDs[1:])
//}
//newParent := layer.ChainID(digest.FromBytes([]byte(string(ancestors[len(ancestors)-1]) + " " + string(diffIDs[0]))))
//newAncestors := append(ancestors, newParent)
//return scanlChainIDRec(newAncestors, diffIDs[1:])
//}

// PushImage encrypts then pushes an image
func PushImage(repotag string) (err error) {
	imgName, manifest, err := EncryptImage(repotag)
	if err != nil {
		return err
	}

	// Upload to registry
	if err = registry.PushImage(user, repo, tag, service, authServer, manifest); err != nil {
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

	tarball, err := DecryptImage(manifest)
	if err != nil {
		return err
	}

	if err = importImage(tarball); err != nil {
		return err
	}

	// cleanup temporary files
	if err = os.RemoveAll(path); err != nil {
		return err
	}

	return nil
}
