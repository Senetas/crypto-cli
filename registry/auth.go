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
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"

	"github.com/docker/cli/cli/config"
	"github.com/docker/distribution/registry/api/v2"
	"github.com/docker/docker/registry"
	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/utils"
)

// Authenticate against the given server, returning the bearer token
func Authenticate(ref NamedRepository, repoInfo registry.RepositoryInfo, endpoint registry.APIEndpoint) (string, error) {
	confFile, err := config.Load("")
	if err != nil {
		return "", err
	}

	authConfig := registry.ResolveAuthConfig(confFile.AuthConfigs, repoInfo.Index)

	bldr := v2.NewURLBuilder(endpoint.URL, false)

	urlStr, err := bldr.BuildBaseURL()
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return "", err
	}

	resp, err := doRequest(&http.Client{}, req, true, false)
	if err != nil {
		return "", err
	}
	defer func() {
		err = utils.CheckedClose(resp.Body, err)
	}()

	var auth string
	if resp.StatusCode == http.StatusUnauthorized {
		auth = resp.Header.Get("Www-Authenticate")
		if auth == "" {
			return "", errors.New("login error")
		}
	} else if resp.StatusCode == http.StatusOK {
		return "", nil
	} else {
		return "", errors.New("login not supported")
	}

	re := regexp.MustCompile("realm=\"(?P<realm>.*)\",service=\"(?P<service>.*)\"")
	matches := re.FindAllStringSubmatch("Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\"", -1)
	realm := matches[0][1]
	service := matches[0][2]

	authToken, err := localAuthToken()
	if err != nil {
		return "", err
	}

	u, err := url.Parse(realm)
	if err != nil {
		return "", err
	}

	q := url.Values{}
	q.Add("account", authConfig.Username)
	q.Add("service", service)
	q.Add("scope", "repository:"+ref.Path()+":pull,push")

	rawQ, err := url.QueryUnescape(q.Encode())
	if err != nil {
		return "", err
	}

	u.RawQuery = rawQ

	req, err = http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Authorization", "Basic "+authToken)

	resp, err = doRequest(&http.Client{}, req, true, false)
	if err != nil {
		return "", err
	}
	defer func() {
		err = utils.CheckedClose(resp.Body, err)
	}()

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("authentication failed with status: " + resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", nil
	}

	var bodyJSON map[string]interface{}
	if err = json.Unmarshal(body, &bodyJSON); err != nil {
		return "", errors.Wrapf(err, "could not unmarshal: %v", body)
	}

	return bodyJSON["token"].(string), nil
}

func localAuthToken() (string, error) {
	dat, err := ioutil.ReadFile(filepath.Join(config.Dir(), "config.json"))
	if err != nil {
		return "", err
	}

	var config map[string]interface{}
	if err = json.Unmarshal(dat, &config); err != nil {
		return "", nil
	}

	for _, v := range config["auths"].(map[string]interface{}) {
		return (v.(map[string]interface{})["auth"]).(string), nil
	}

	return "", errors.New("No Authentication Token was found. Try to run \"docker login\"")
}
