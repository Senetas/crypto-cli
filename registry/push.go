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

package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	//"os"

	"github.com/docker/distribution/reference"
	"github.com/docker/distribution/registry/api/v2"
	"github.com/docker/docker/registry"
	"github.com/rs/zerolog/log"

	cref "github.com/Senetas/crypto-cli/reference"
	"github.com/Senetas/crypto-cli/types"
	"github.com/Senetas/crypto-cli/utils"
)

// PushImage pushes the config, layers and mainifest to the nominated registry, in that order
func PushImage(user, service, authServer string, ref *reference.Named, manifest *types.ImageManifestJSON, endpoint *registry.APIEndpoint) error {
	repo, _, err := cref.ResloveNamed(ref)
	if err != nil {
		return err
	}

	// Authenticate with the Auth server
	token, err := Authenticate(user, service, repo, authServer)
	if err != nil {
		return err
	}

	if err = PushLayer(token, ref, manifest.Config, endpoint); err != nil {
		return err
	}
	for _, l := range manifest.Layers {
		if err = PushLayer(token, ref, l, endpoint); err != nil {
			return err
		}
	}
	log.Info().Msg("Layers and config uploaded successfully")

	mdigest, err := PushManifest(token, ref, manifest, endpoint)
	if err != nil {
		return err
	}
	log.Info().Msgf("Successfully uploaded manifest with digest: %s\n", mdigest)

	return nil
}

// PushManifest puts a manifest on the registry
func PushManifest(token string, ref *reference.Named, manifest *types.ImageManifestJSON, endpoint *registry.APIEndpoint) (string, error) {
	manifestJSON, err := json.MarshalIndent(manifest, "", "\t")
	if err != nil {
		return "", err
	}

	builder := v2.NewURLBuilder(endpoint.URL, false)
	urlStr, err := builder.BuildManifestURL(*ref)
	if err != nil {
		return "", err
	}

	client := &http.Client{}
	req, err := http.NewRequest("PUT", urlStr, bytes.NewReader(manifestJSON))
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/json, */*")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")

	resp, err := doRequest(client, req, true, true)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusCreated {
		return "", errors.New("manifest upload failed with status: " + resp.Status)
	}

	if err = resp.Body.Close(); err != nil {
		return "", err
	}

	return resp.Header.Get("Docker-Content-Digest"), nil
}

// PushLayer pushes a layer to the registry, checking if it exists
func PushLayer(token string, ref *reference.Named, layerData *types.LayerJSON, endpoint *registry.APIEndpoint) (err error) {
	canonical, err := reference.WithDigest(*ref, *layerData.Digest)
	if err != nil {
		return err
	}

	bldr := v2.NewURLBuilder(endpoint.URL, false)

	layerExists, err := checkLayer(token, &canonical, bldr)
	if err != nil {
		log.Info().Msg("error pushing layer")
		return err
	} else if layerExists {
		log.Info().Msgf("Layer %s exists.", layerData.Digest)
		return nil
	}

	// get the location to upload the blob
	uploadURLStr, err := bldr.BuildBlobUploadURL(*ref, nil)
	if err != nil {
		return err
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", uploadURLStr, nil)
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := doRequest(client, req, true, true)
	if err != nil {
		return err
	}
	defer func() {
		err = utils.CheckedClose(resp.Body, err)
	}()

	if resp.StatusCode != http.StatusAccepted {
		return errors.New("upload of layer " + layerData.Digest.String() + " was not accepted")
	}

	// now actually upload the blob
	u := resp.Header.Get("Location")
	if u == "" {
		return errors.New("server did not return navigation link")
	}

	uuid := resp.Header.Get("Uuid")
	if uuid == "" {
		return errors.New("server did not return uuid")
	}

	bldr, err = v2.NewURLBuilderFromString(u, false)
	if err != nil {
		return err
	}

	chunckURL, err := bldr.BuildBlobUploadChunkURL(*ref, uuid, nil)
	if err != nil {
		return err
	}

	println(chunckURL)

	//q, err := url.ParseQuery(u.RawQuery)
	//if err != nil {
	//return err
	//}
	//q.Add("digest", layerData.Digest.String())
	//rawq, err := url.QueryUnescape(q.Encode())
	//if err != nil {
	//return err
	//}
	//u.RawQuery = rawq

	//// open the layer file to get size and upload
	//layerFH, err := os.Open(layerData.Filename)
	//if err != nil {
	//return err
	//}
	//defer func() {
	//err = utils.CheckedClose(layerFH, err)
	//}()

	//stat, err := layerFH.Stat()
	//if err != nil {
	//return err
	//}

	//req, err = http.NewRequest("PUT", u.String(), layerFH)
	//if err != nil {
	//return err
	//}

	//req.Header.Add("Authorization", "Bearer "+token)
	//req.Header.Add("Content-Length", strconv.FormatInt(stat.Size(), 10))
	//req.Header.Add("Content-Type", "application/octect-stream")

	//resp, err = doRequest(client, req, false, true)
	//if err != nil {
	//return err
	//}
	//defer func() {
	//err = utils.CheckedClose(resp.Body, err)
	//}()

	//if resp.StatusCode != http.StatusCreated {
	//return errors.New("upload of layer " + layerData.Digest.String() + " failed")
	//}

	return nil
}

func checkLayer(token string, ref *reference.Canonical, bldr *v2.URLBuilder) (b bool, err error) {
	layerURLStr, err := bldr.BuildBlobUploadURL(*ref, nil)
	if err != nil {
		return false, err
	}

	client := &http.Client{}
	req, err := http.NewRequest("HEAD", layerURLStr, nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := doRequest(client, req, true, true)
	if err != nil {
		return false, err
	}
	defer func() {
		b = false
		err = utils.CheckedClose(resp.Body, err)
	}()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	} else if resp.StatusCode == http.StatusNotFound {
		return false, nil
	} else {
		log.Fatal().Msg("error testing exsistance of layer")
	}
	return false, nil
}
