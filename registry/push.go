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
	//"net/http/httputil"
	"net/url"

	"github.com/Senetas/crypto-cli/types"
)

// PutManifest puts a manifest on the registry
func PutManifest(user, repo, tag string, manifest *types.ImageManifestJSON) (string, error) {
	authToken, err := AuthToken()
	if err != nil {
		return "", err
	}

	token, err := Authenticate(user, "registry.docker.io", repo, "auth.docker.io", authToken)
	if err != nil {
		return "", err
	}

	digest, err := putManifest("registry-1.docker.io", "v2", repo, tag, token, manifest)
	if err != nil {
		return "", err
	}

	return digest, nil
}

func putManifest(regAddr, regPath, repo, tag, token string, manifest *types.ImageManifestJSON) (string, error) {
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
