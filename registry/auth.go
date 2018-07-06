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

	"github.com/pkg/errors"

	"github.com/Senetas/crypto-cli/utils"
	"github.com/docker/docker/cli/config"
)

// Authenticate against the given server, returning the bearer token
func Authenticate(user, service, authServer string, ref NamedRepository) (string, error) {
	authToken, err := localAuthToken()
	if err != nil {
		return "", err
	}

	u := url.URL{
		Scheme: "https",
		Host:   authServer,
		Path:   "token"}
	q := url.Values{}
	q.Add("account", user)
	q.Add("service", service)
	q.Add("scope", "repository:"+ref.Path()+":pull,push")

	rawQ, err := url.QueryUnescape(q.Encode())
	if err != nil {
		return "", err
	}

	u.RawQuery = rawQ

	client := &http.Client{}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Authorization", "Basic "+authToken)

	resp, err := doRequest(client, req, true, false)
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
	json.Unmarshal(body, &bodyJSON)

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
