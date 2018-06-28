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
	//"net/http/httputil"
	"net/url"
	"os"
	"strconv"

	"github.com/Senetas/crypto-cli/types"
	"github.com/Senetas/crypto-cli/utils"
)

// PushManifest puts a manifest on the registry
func PushManifest(user, repo, tag, token string, manifest *types.ImageManifestJSON) (string, error) {
	digest, err := pushManifest("registry-1.docker.io", "v2", repo, tag, token, manifest)
	if err != nil {
		return "", err
	}

	return digest, nil
}

func pushManifest(regAddr, regPath, repo, tag, token string, manifest *types.ImageManifestJSON) (string, error) {
	manifestJSON, err := json.MarshalIndent(manifest, "", "\t")
	if err != nil {
		return "", err
	}

	u := url.URL{
		Scheme: "https",
		Host:   regAddr,
		Path:   regPath + "/" + repo + "/" + "manifests" + "/" + tag}

	client := &http.Client{}
	req, err := http.NewRequest("PUT", u.String(), bytes.NewReader(manifestJSON))
	if err != nil {
		return "", err
	}

	req.Header.Add("Accept", "application/json, */*")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Type", "application/vnd.docker.distribution.manifest.list.v2+json")

	//dump, err := httputil.DumpRequestOut(req, true)
	//if err != nil {
	//return err
	//}

	//fmt.Println(string(dump))

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusCreated {
		return "", errors.New("manifest upload failed with status: " + resp.Status)
	}
	resp.Body.Close()

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

	u := url.URL{
		Scheme: "https",
		Host:   "registry-1.docker.io",
		Path:   "v2/" + repo + "/blobs/uploads/"}
	q := url.Values{}
	q.Add("digest", layerData.Digest)

	rawQ, err := url.QueryUnescape(q.Encode())
	if err != nil {
		return err
	}
	u.RawQuery = rawQ

	layerFile, err := os.Open(layerData.Filename)
	if err != nil {
		return err
	}

	stat, err := layerFile.Stat()
	if err != nil {
		return err
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", u.String(), layerFile)
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Content-Length", strconv.FormatInt(stat.Size(), 10))
	req.Header.Add("Content-Type", "application/octect-stream")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		err = utils.CheckedClose(resp.Body)
	}()

	//dump, err := httputil.DumpResponse(resp, true)
	//if err != nil {
	//return err
	//}
	//fmt.Println(string(dump))

	if resp.StatusCode == http.StatusAccepted {
		return nil
	}

	return errors.New("upload of layer " + layerData.Digest + " failed")
}

func checkLayer(user, repo, token, digest string) (b bool, err error) {
	u := url.URL{
		Scheme: "https",
		Host:   "registry-1.docker.io",
		Path:   "v2/" + repo + "/" + "blobs" + "/" + digest}

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
		err = utils.CheckedClose(resp.Body)
	}()

	//dump, err := httputil.DumpRequestOut(req, true)
	//if err != nil {
	//return false, err
	//}
	//fmt.Println(string(dump))

	return resp.StatusCode == http.StatusOK, nil
}
