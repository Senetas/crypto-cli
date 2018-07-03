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
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"

	"github.com/Senetas/crypto-cli/types"
	"github.com/Senetas/crypto-cli/utils"
)

// PushImage pushes the config, layers and mainifest to the nominated registry, in that order
func PushImage(user, repo, tag, service, authServer string, manifest *types.ImageManifestJSON) error {
	// Authenticate with the Auth server
	token, err := Authenticate(user, service, repo, authServer)

	if err = PushLayer(user, repo, tag, token, manifest.Config); err != nil {
		return err
	}
	for _, l := range manifest.Layers {
		if err = PushLayer(user, repo, tag, token, l); err != nil {
			return err
		}
	}
	fmt.Println("Layers and config uploaded successfully")

	mdigest, err := PushManifest(user, repo, tag, token, manifest)
	if err != nil {
		return err
	}
	fmt.Printf("Successfully uploaded manifest with digest: %s\n", mdigest)

	return nil
}

// PushManifest puts a manifest on the registry
func PushManifest(user, repo, tag, token string, manifest *types.ImageManifestJSON) (string, error) {
	regAddr := "registry-1.docker.io"
	regPath := "v2"

	manifestJSON, err := json.MarshalIndent(manifest, "", "\t")
	if err != nil {
		return "", err
	}

	u := &url.URL{
		Scheme: "https",
		Host:   regAddr,
		Path:   path.Join(regPath, repo, "manifests", tag)}

	client := &http.Client{}
	req, err := http.NewRequest("PUT", u.String(), bytes.NewReader(manifestJSON))
	if err != nil {
		return "", err
	}

	req.Header.Set("Accept", "application/json, */*")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")

	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return "", err
	}
	fmt.Println(string(dump))

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	dump, err = httputil.DumpResponse(resp, true)
	if err != nil {
		return "", err
	}
	fmt.Println(string(dump))

	if resp.StatusCode != http.StatusCreated {
		return "", errors.New("manifest upload failed with status: " + resp.Status)
	}

	if err = resp.Body.Close(); err != nil {
		return "", err
	}

	return resp.Header.Get("Docker-Content-Digest"), nil
}

// PushLayer pushes a layer to the registry, checking if it exists
func PushLayer(user, repo, tag, token string, layerData *types.LayerJSON) (err error) {
	layerExists, err := checkLayer(user, repo, token, layerData.Digest)
	if err != nil {
		return err
	}

	if layerExists {
		fmt.Println("Layer " + layerData.Digest + " exists")
		return nil
	}

	// get the location to upload the blob
	u := &url.URL{
		Scheme: "https",
		Host:   "registry-1.docker.io",
		Path:   utils.PathTrailingJoin("v2", repo, "blobs", "uploads")}

	client := &http.Client{}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", "Bearer "+token)

	dump, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return err
	}
	fmt.Println(string(dump))

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		err = utils.CheckedClose(resp.Body, err)
	}()

	dump, err = httputil.DumpResponse(resp, true)
	if err != nil {
		return err
	}
	fmt.Println(string(dump))

	if resp.StatusCode != http.StatusAccepted {
		return errors.New("upload of layer " + layerData.Digest + " was not accepted")
	}

	// now actually upload the blob
	u, err = url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return err
	}

	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return err
	}
	q.Add("digest", layerData.Digest)
	rawq, err := url.QueryUnescape(q.Encode())
	if err != nil {
		return err
	}
	u.RawQuery = rawq

	// open the layer file to get size and upload
	layerFH, err := os.Open(layerData.Filename)
	if err != nil {
		return err
	}
	defer func() {
		err = utils.CheckedClose(layerFH, err)
	}()

	stat, err := layerFH.Stat()
	if err != nil {
		return err
	}

	req, err = http.NewRequest("PUT", u.String(), layerFH)
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Length", strconv.FormatInt(stat.Size(), 10))
	req.Header.Add("Content-Type", "application/octect-stream")

	dump, err = httputil.DumpRequestOut(req, false)
	if err != nil {
		return err
	}
	fmt.Println(string(dump))

	resp, err = client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		err = utils.CheckedClose(resp.Body, err)
	}()

	dump, err = httputil.DumpResponse(resp, true)
	if err != nil {
		return err
	}
	fmt.Println(string(dump))

	if resp.StatusCode != http.StatusCreated {
		return errors.New("upload of layer " + layerData.Digest + " failed")
	}

	return nil
}

func checkLayer(user, repo, token, digest string) (b bool, err error) {
	u := url.URL{
		Scheme: "https",
		Host:   "registry-1.docker.io",
		Path:   path.Join("v2", repo, "blobs", digest)}

	client := &http.Client{}
	req, err := http.NewRequest("HEAD", u.String(), nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		b = false
		err = utils.CheckedClose(resp.Body, err)
	}()

	//dump, err := httputil.DumpRequestOut(req, true)
	//if err != nil {
	//return false, err
	//}
	//fmt.Println(string(dump))

	return resp.StatusCode == http.StatusOK, nil
}
